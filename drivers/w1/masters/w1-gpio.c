// SPDX-License-Identifier: GPL-2.0-only
/*
 * w1-gpio - GPIO w1 bus master driver
 *
 * Copyright (C) 2007 Ville Syrjala <syrjala@sci.fi>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/w1-gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/of_platform.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/delay.h>

#include <linux/w1.h>

static u8 w1_gpio_set_pullup(void *data, int delay)
{
	struct w1_gpio_platform_data *pdata = data;

	if (delay) {
		pdata->pullup_duration = delay;
	} else {
		if (pdata->pullup_duration) {
			/*
			 * This will OVERRIDE open drain emulation and force-pull
			 * the line high for some time.
			 */
			gpiod_direction_output_raw(pdata->gpiod, 1);
			msleep(pdata->pullup_duration);
			/*
			 * This will simply set the line as input since we are doing
			 * open drain emulation in the GPIO library.
			 */
			gpiod_set_value(pdata->gpiod, 1);
		}
		pdata->pullup_duration = 0;
	}

	return 0;
}

static void w1_gpio_write_bit(void *data, u8 bit)
{
	struct w1_gpio_platform_data *pdata = data;

	gpiod_set_value(pdata->gpiod, bit);
}

static u8 w1_gpio_read_bit(void *data)
{
	struct w1_gpio_platform_data *pdata = data;

	return gpiod_get_value(pdata->gpiod) ? 1 : 0;
}

#if defined(CONFIG_OF)
static const struct of_device_id w1_gpio_dt_ids[] = {
	{ .compatible = "w1-gpio" },
	{}
};
MODULE_DEVICE_TABLE(of, w1_gpio_dt_ids);
#endif

static int w1_gpio_probe(struct platform_device *pdev)
{
    struct w1_bus_master *master;
    struct w1_gpio_platform_data *pdata;
    struct device *dev = &pdev->dev;
    struct device_node *np = dev->of_node;
    /* Enforce open drain mode by default */
    enum gpiod_flags gflags = GPIOD_OUT_LOW_OPEN_DRAIN;
    int err;
    u32 temp[20 * 2]; // 40 to accommodate 20 pairs of 32-bit integers (20 64-bit values)

    master = devm_kzalloc(dev, sizeof(struct w1_bus_master), GFP_KERNEL);
    if (!master)
        return -ENOMEM;

    if (of_have_populated_dt()) {
        pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
        if (!pdata)
            return -ENOMEM;

        /*
         * This parameter means that something else than the gpiolib has
         * already set the line into open drain mode, so we should just
         * drive it high/low like we are in full control of the line and
         * open drain will happen transparently.
         */
        if (of_property_present(np, "linux,open-drain"))
            gflags = GPIOD_OUT_LOW;

        // Initialize delay_needs_poll based on the device tree property
        if (of_property_present(np, "raspberrypi,delay-needs-poll")) {
            master->delay_needs_poll = true;
            dev_info(dev, "raspberrypi,delay-needs-poll property is present, setting delay_needs_poll to true\n");
        } else {
            master->delay_needs_poll = false;
            dev_info(dev, "raspberrypi,delay-needs-poll property is not present, setting delay_needs_poll to false\n");
        }

        // GPIO master supports overdriver mode
        master->supports_overdrive_mode = true;

        // Read and handle optional properties with default values
        if (of_find_property(np, "write_bit_0_avg_ns", NULL)) {
            if (of_property_read_u64(np, "write_bit_0_avg_ns", &pdata->write_bit_0_avg_ns)) {
                pdata->write_bit_0_avg_ns = 500; // Default value
                dev_warn(dev, "Failed to read write_bit_0_avg_ns, using default: %llu\n", pdata->write_bit_0_avg_ns);
            } else {
                dev_info(dev, "write_bit_0_avg_ns: %llu\n", pdata->write_bit_0_avg_ns);
            }
        } else {
            pdata->write_bit_0_avg_ns = 500; // Default value
            dev_info(dev, "write_bit_0_avg_ns property not found, using default: %llu\n", pdata->write_bit_0_avg_ns);
        }

        if (of_find_property(np, "write_bit_1_avg_ns", NULL)) {
            if (of_property_read_u64(np, "write_bit_1_avg_ns", &pdata->write_bit_1_avg_ns)) {
                pdata->write_bit_1_avg_ns = 500; // Default value
                dev_warn(dev, "Failed to read write_bit_1_avg_ns, using default: %llu\n", pdata->write_bit_1_avg_ns);
            } else {
                dev_info(dev, "write_bit_1_avg_ns: %llu\n", pdata->write_bit_1_avg_ns);
            }
        } else {
            pdata->write_bit_1_avg_ns = 500; // Default value
            dev_info(dev, "write_bit_1_avg_ns property not found, using default: %llu\n", pdata->write_bit_1_avg_ns);
        }

        if (of_find_property(np, "read_bit_avg_ns", NULL)) {
            if (of_property_read_u64(np, "read_bit_avg_ns", &pdata->read_bit_avg_ns)) {
                pdata->read_bit_avg_ns = 300; // Default value
                dev_warn(dev, "Failed to read read_bit_avg_ns, using default: %llu\n", pdata->read_bit_avg_ns);
            } else {
                dev_info(dev, "read_bit_avg_ns: %llu\n", pdata->read_bit_avg_ns);
            }
        } else {
            pdata->read_bit_avg_ns = 300; // Default value
            dev_info(dev, "read_bit_avg_ns property not found, using default: %llu\n", pdata->read_bit_avg_ns);
        }

         // Check if the w1_delay_values property exists
        if (of_find_property(np, "w1_delay_values", NULL)) {
            // Attempt to read the w1_delay_values property
            if (of_property_read_u32_array(np, "w1_delay_values", temp, 20 * 2)) {
                dev_warn(&pdev->dev, "Failed to read w1_delay_values\n");
                // Use default values if reading failed
                static u64 w1_delay_values[10][2] = {
                    {6 * 1000,    1 * 1000},
                    {64 * 1000,   7.5 * 1000},
                    {60 * 1000,   7.5 * 1000},
                    {10 * 1000,   5 * 1000},
                    {9 * 1000,    0.5 * 1000}, // changed from 1 to 0.5 for overdrive
                    {55 * 1000,   7 * 1000},
                    {0 * 1000,    2.5 * 1000},
                    {480 * 1000,  50 * 1000}, // changed from 70 to 50 for overdrive
                    {70 * 1000,   10 * 1000},
                    {485 * 1000,  50 * 1000}
                };

                memcpy(pdata->w1_delay_values, w1_delay_values, sizeof(w1_delay_values));
            } else {
                // Populate pdata->w1_delay_values and print each pair
                for (int i = 0; i < 10; i++) {
                    for (int j = 0; j < 2; j++) {
                        pdata->w1_delay_values[i][j] = ((u64)temp[i * 4 + j * 2] << 32) | temp[i * 4 + j * 2 + 1];
                    }
                }
                for (int i = 0; i < 10; i++) {
                    dev_info(&pdev->dev, "w1_delay_values[%d][0]: %llu, w1_delay_values[%d][1]: %llu\n",
                             i, pdata->w1_delay_values[i][0], i, pdata->w1_delay_values[i][1]);
                }
            }
        } else {
            dev_info(&pdev->dev, "w1_delay_values property not found in device tree\n");
            // Use default values if property is not found
            static u64 w1_delay_values[10][2] = {
                {6 * 1000,    1 * 1000},
                {64 * 1000,   7.5 * 1000},
                {60 * 1000,   7.5 * 1000},
                {10 * 1000,   5 * 1000},
                {9 * 1000,    0.5 * 1000}, // changed from 1 to 0.5 for overdrive
                {55 * 1000,   7 * 1000},
                {0 * 1000,    2.5 * 1000},
                {480 * 1000,  50 * 1000}, // changed from 70 to 50 for overdrive
                {70 * 1000,   10 * 1000},
                {485 * 1000,  50 * 1000}
            };

            memcpy(pdata->w1_delay_values, w1_delay_values, sizeof(w1_delay_values));
        }

        pdev->dev.platform_data = pdata;
    }

    pdata = dev_get_platdata(dev);

    if (!pdata) {
        dev_err(dev, "No configuration data\n");
        return -ENXIO;
    }

    pdata->gpiod = devm_gpiod_get_index(dev, NULL, 0, gflags);
    if (IS_ERR(pdata->gpiod)) {
        dev_err(dev, "gpio_request (pin) failed\n");
        return PTR_ERR(pdata->gpiod);
    }

    pdata->pullup_gpiod =
        devm_gpiod_get_index_optional(dev, NULL, 1, GPIOD_OUT_LOW);
    if (IS_ERR(pdata->pullup_gpiod)) {
		dev_err(dev, "gpio_request_one "
			"(ext_pullup_enable_pin) failed\n");
        return PTR_ERR(pdata->pullup_gpiod);
    }

    master->data = pdata;
    master->read_bit = w1_gpio_read_bit;
    gpiod_direction_output(pdata->gpiod, 1);
    master->write_bit = w1_gpio_write_bit;

    /*
     * If we are using open drain emulation from the GPIO library,
     * we need to use this pullup function that hammers the line
     * high using a raw accessor to provide pull-up for the w1
     * line.
     */
    if (gflags == GPIOD_OUT_LOW_OPEN_DRAIN)
        master->set_pullup = w1_gpio_set_pullup;

    err = w1_add_master_device(master);
    if (err) {
        dev_err(dev, "w1_add_master device failed\n");
        return err;
    }

    if (pdata->enable_external_pullup)
        pdata->enable_external_pullup(1);

    if (pdata->pullup_gpiod)
        gpiod_set_value(pdata->pullup_gpiod, 1);

    platform_set_drvdata(pdev, master);

    return 0;
}

static int w1_gpio_remove(struct platform_device *pdev)
{
	struct w1_bus_master *master = platform_get_drvdata(pdev);
	struct w1_gpio_platform_data *pdata = dev_get_platdata(&pdev->dev);

	if (pdata->enable_external_pullup)
		pdata->enable_external_pullup(0);

	if (pdata->pullup_gpiod)
		gpiod_set_value(pdata->pullup_gpiod, 0);

	w1_remove_master_device(master);

	return 0;
}

static int __maybe_unused w1_gpio_suspend(struct device *dev)
{
	struct w1_gpio_platform_data *pdata = dev_get_platdata(dev);

	if (pdata->enable_external_pullup)
		pdata->enable_external_pullup(0);

	return 0;
}

static int __maybe_unused w1_gpio_resume(struct device *dev)
{
	struct w1_gpio_platform_data *pdata = dev_get_platdata(dev);

	if (pdata->enable_external_pullup)
		pdata->enable_external_pullup(1);

	return 0;
}

static SIMPLE_DEV_PM_OPS(w1_gpio_pm_ops, w1_gpio_suspend, w1_gpio_resume);

static struct platform_driver w1_gpio_driver = {
	.driver = {
		.name	= "w1-gpio",
		.pm	= &w1_gpio_pm_ops,
		.of_match_table = of_match_ptr(w1_gpio_dt_ids),
	},
	.probe = w1_gpio_probe,
	.remove = w1_gpio_remove,
};

module_platform_driver(w1_gpio_driver);

MODULE_DESCRIPTION("GPIO w1 bus master driver");
MODULE_AUTHOR("Ville Syrjala <syrjala@sci.fi>");
MODULE_LICENSE("GPL");
