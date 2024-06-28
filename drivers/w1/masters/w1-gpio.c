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

	master = devm_kzalloc(dev, sizeof(struct w1_bus_master),
			GFP_KERNEL);
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

		pr_info("Reading overdrive_mode parameter.\n");
        /* Read the overdrive_mode from the device tree */
        if (of_find_property(np, "overdrive_mode", NULL)) {
            u32 overdrive_mode_val;
            if (!of_property_read_u32(np, "overdrive_mode", &overdrive_mode_val)) {
                pdata->overdrive_mode = overdrive_mode_val; // Directly assign the integer value
                dev_info(dev, "Overdrive mode set to: %u\n", pdata->overdrive_mode);
            } else {
                /* Error handling if unable to read overdrive_mode property */
                pdata->overdrive_mode = 0;  // Default to 0 or handle accordingly
                dev_warn(dev, "Failed to read overdrive_mode property. Defaulting to 0.\n");
            }
        } else {
            /* Default behavior if overdrive_mode property is not present */
            pdata->overdrive_mode = 0;  // Default to 0 or handle accordingly
            dev_info(dev, "Overdrive mode property not found. Defaulting to 0.\n");
        }

		master->overdrive_mode = pdata->overdrive_mode;

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
