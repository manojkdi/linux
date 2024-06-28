// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2004 Evgeniy Polyakov <zbr@ioremap.net>
 */

#include <asm/io.h>

#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/moduleparam.h>
#include <linux/module.h>

#include "w1_internal.h"

#define AVERAGE_SAMPLES 100

static s64 write_bit_0_avg_ns = 0;
static s64 write_bit_1_avg_ns = 0;
static s64 read_bit_avg_ns = 0;
static s64 measurement_overhead_ns = 0;


static int w1_delay_parm = 1;
module_param_named(delay_coef, w1_delay_parm, int, 0);

static int w1_disable_irqs = 1;
module_param_named(disable_irqs, w1_disable_irqs, int, 0);

static u8 w1_crc8_table[] = {
	0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
	157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
	35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
	190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
	70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
	219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
	101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
	248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
	140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
	17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
	175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
	50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
	202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
	87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
	233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
	116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53
};

static unsigned long delay_values[10][2] =    {{6 * 1000,    1 * 1000},
                                               {64 * 1000,  7.5 * 1000},
                                               {60 * 1000,   7.5 * 1000},
                                               {10 * 1000,   5 * 1000},
                                               {9 * 1000,    .5 * 1000},//changed from 1 to .5 for overdrive
                                               {55 * 1000,   7 * 1000},
                                               {0 * 1000,    2.5 * 1000},
                                               {480 * 1000, 50 * 1000},//changed from 70 t0 50 for overdrive
                                               {70 * 1000,   10 * 1000},
                                               {485 * 1000,   50 * 1000}
                                              };

static void update_average(s64 *avg, s64 new_value)
{
    *avg = ((*avg * (AVERAGE_SAMPLES - 1)) + new_value) / AVERAGE_SAMPLES;
}

static s64 measure_overhead(void)
{
    ktime_t start, end;
    start = ktime_get();
    end = ktime_get();
    s64 overhead = ktime_to_ns(ktime_sub(end, start));

    start = ktime_get();
    update_average(&write_bit_0_avg_ns, 0);  // Dummy call to include averaging overhead
    end = ktime_get();
    overhead += ktime_to_ns(ktime_sub(end, start));

    return overhead;
}

/**
 * @brief This function implements a delay for 1-Wire communication.
 *
 * The function calculates the delay time in microseconds and nanoseconds based on the input parameter.
 * It then checks if the bus master requires polling. If not, it simply applies the delay.
 * If polling is required, it enters a loop where it reads a bit from the bus master and applies a short delay,
 * repeating this process until the desired delay time has been reached.
 *
 * @param dev Pointer to the 1-Wire master device structure.
 * @param tm The desired delay time in microseconds.
 *
 * For more details, please refer to the following resource:
 * [1-Wire Communication Through Software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
 */
static void w1_delay(struct w1_master *dev, unsigned long delay_ns)
{
    ktime_t start, delta;
    unsigned long delay_us, delay_remainder_ns;

	if(delay_ns == 0)
	{
		return;
	}

    if (!dev->bus_master->delay_needs_poll) {
        delay_us = delay_ns / 1000; // convert nanoseconds to microseconds
        delay_remainder_ns = delay_ns % 1000; // remainder in nanoseconds

        if (delay_us > 0)
            udelay(delay_us * w1_delay_parm);
        if (delay_remainder_ns > 0)
            ndelay(delay_remainder_ns * w1_delay_parm);

        return;
    }

    start = ktime_get();
    delta = ktime_add(start, ns_to_ktime(delay_ns * w1_delay_parm));
    do {
        dev->bus_master->read_bit(dev->bus_master->data);
        if (delay_ns > 1000) {
            udelay(1); // delay of 1 microsecond
            delay_ns -= 1000;
        } else {
            ndelay(delay_ns); // delay of remaining nanoseconds
            delay_ns = 0;
        }
    } while (ktime_before(ktime_get(), delta));
}



static void w1_write_bit(struct w1_master *dev, int bit);
static u8 w1_read_bit(struct w1_master *dev);

/**
 * w1_touch_bit() - Generates a write-0 or write-1 cycle and samples the level.
 * @dev:	the master device
 * @bit:	0 - write a 0, 1 - write a 0 read the level
 */
u8 w1_touch_bit(struct w1_master *dev, int bit)
{
	if (dev->bus_master->touch_bit)
		return dev->bus_master->touch_bit(dev->bus_master->data, bit);
	else if (bit)
		return w1_read_bit(dev);
	else {
		w1_write_bit(dev, 0);
		return 0;
	}
}
EXPORT_SYMBOL_GPL(w1_touch_bit);

/**
 * w1_write_bit() - Generates a write-0 or write-1 cycle.
 * @dev:	the master device
 * @bit:	bit to write
 *
 * Only call if dev->bus_master->touch_bit is NULL
 */
static void w1_write_bit(struct w1_master *dev, int bit)
{
    unsigned long flags = 0;
    ktime_t start, end;
    s64 elapsed_ns;
    s64 delay_ns;

    // Measure overhead if not already done
    if (measurement_overhead_ns == 0) {
        measurement_overhead_ns = measure_overhead();
    }

    if (w1_disable_irqs)
        local_irq_save(flags);

    if (bit) {
        // Measure time taken by write_bit(0)
        start = ktime_get();
        dev->bus_master->write_bit(dev->bus_master->data, 0);
        end = ktime_get();
        elapsed_ns = ktime_to_ns(ktime_sub(end, start)) - measurement_overhead_ns;
        update_average(&write_bit_0_avg_ns, elapsed_ns);

        // Adjust delay for the next write_bit call
        delay_ns = delay_values[0][dev->overdrive_mode_active] - write_bit_0_avg_ns;
        if (delay_ns > 0)
            w1_delay(dev, delay_ns);

        // Measure time taken by write_bit(1)
        start = ktime_get();
        dev->bus_master->write_bit(dev->bus_master->data, 1);
        end = ktime_get();
        elapsed_ns = ktime_to_ns(ktime_sub(end, start)) - measurement_overhead_ns;
        update_average(&write_bit_1_avg_ns, elapsed_ns);

        // Adjust delay for the next operation
        delay_ns = delay_values[1][dev->overdrive_mode_active] - write_bit_1_avg_ns;
        if (delay_ns > 0)
            w1_delay(dev, delay_ns);

    } else {
        // Measure time taken by write_bit(0)
        start = ktime_get();
        dev->bus_master->write_bit(dev->bus_master->data, 0);
        end = ktime_get();
        elapsed_ns = ktime_to_ns(ktime_sub(end, start)) - measurement_overhead_ns;
        update_average(&write_bit_0_avg_ns, elapsed_ns);

        // Adjust delay for the next write_bit call
        delay_ns = delay_values[2][dev->overdrive_mode_active] - write_bit_0_avg_ns;
        if (delay_ns > 0)
            w1_delay(dev, delay_ns);

        // Measure time taken by write_bit(1)
        start = ktime_get();
        dev->bus_master->write_bit(dev->bus_master->data, 1);
        end = ktime_get();
        elapsed_ns = ktime_to_ns(ktime_sub(end, start)) - measurement_overhead_ns;
        update_average(&write_bit_1_avg_ns, elapsed_ns);

        // Adjust delay for the next operation
        delay_ns = delay_values[3][dev->overdrive_mode_active] - write_bit_1_avg_ns;
        if (delay_ns > 0)
            w1_delay(dev, delay_ns);
    }

    if (w1_disable_irqs)
        local_irq_restore(flags);
}

/**
 * w1_pre_write() - pre-write operations
 * @dev:	the master device
 *
 * Pre-write operation, currently only supporting strong pullups.
 * Program the hardware for a strong pullup, if one has been requested and
 * the hardware supports it.
 */
static void w1_pre_write(struct w1_master *dev)
{
	if (dev->pullup_duration &&
		dev->enable_pullup && dev->bus_master->set_pullup) {
		dev->bus_master->set_pullup(dev->bus_master->data,
			dev->pullup_duration);
	}
}

/**
 * w1_post_write() - post-write options
 * @dev:	the master device
 *
 * Post-write operation, currently only supporting strong pullups.
 * If a strong pullup was requested, clear it if the hardware supports
 * them, or execute the delay otherwise, in either case clear the request.
 */
static void w1_post_write(struct w1_master *dev)
{
	if (dev->pullup_duration) {
		if (dev->enable_pullup && dev->bus_master->set_pullup)
			dev->bus_master->set_pullup(dev->bus_master->data, 0);
		else
			msleep(dev->pullup_duration);
		dev->pullup_duration = 0;
	}
}

/**
 * w1_write_8() - Writes 8 bits.
 * @dev:	the master device
 * @byte:	the byte to write
 */
void w1_write_8(struct w1_master *dev, u8 byte)
{
	int i;

	if (dev->bus_master->write_byte) {
		w1_pre_write(dev);
		dev->bus_master->write_byte(dev->bus_master->data, byte);
	}
	else
		for (i = 0; i < 8; ++i) {
			if (i == 7)
				w1_pre_write(dev);
			w1_touch_bit(dev, (byte >> i) & 0x1);
		}
	w1_post_write(dev);
}
EXPORT_SYMBOL_GPL(w1_write_8);


/**
 * w1_read_bit() - Generates a write-1 cycle and samples the level.
 * @dev:	the master device
 *
 * Only call if dev->bus_master->touch_bit is NULL
 */
static u8 w1_read_bit(struct w1_master *dev)
{
    int result;
    unsigned long flags = 0;
    ktime_t start, end;
    s64 elapsed_ns;
    s64 delay_ns;

    // Measure overhead if not already done
    if (measurement_overhead_ns == 0) {
        measurement_overhead_ns = measure_overhead();
    }

    /* sample timing is critical here */
    local_irq_save(flags);

    // Measure time taken by write_bit(0)
    start = ktime_get();
    dev->bus_master->write_bit(dev->bus_master->data, 0);
    end = ktime_get();
    elapsed_ns = ktime_to_ns(ktime_sub(end, start)) - measurement_overhead_ns;
    update_average(&write_bit_0_avg_ns, elapsed_ns);

    // Adjust delay for the next write_bit call
    delay_ns = delay_values[0][dev->overdrive_mode_active] - write_bit_0_avg_ns;
    if (delay_ns > 0)
        w1_delay(dev, delay_ns);

    // Measure time taken by write_bit(1)
    start = ktime_get();
    dev->bus_master->write_bit(dev->bus_master->data, 1);
    end = ktime_get();
    elapsed_ns = ktime_to_ns(ktime_sub(end, start)) - measurement_overhead_ns;
    update_average(&write_bit_1_avg_ns, elapsed_ns);

    // Adjust delay for the next read_bit call
    delay_ns = delay_values[4][dev->overdrive_mode_active] - write_bit_1_avg_ns;
    if (delay_ns > 0)
        w1_delay(dev, delay_ns);

    // Measure time taken by read_bit
    start = ktime_get();
    result = dev->bus_master->read_bit(dev->bus_master->data);
    end = ktime_get();
    elapsed_ns = ktime_to_ns(ktime_sub(end, start)) - measurement_overhead_ns;
    update_average(&read_bit_avg_ns, elapsed_ns);

    local_irq_restore(flags);

    // Adjust delay for the subsequent operation (if any)
    delay_ns = delay_values[5][dev->overdrive_mode_active] - read_bit_avg_ns;
    if (delay_ns > 0)
        w1_delay(dev, delay_ns);

    return result & 0x1;
}

/**
 * w1_triplet() - * Does a triplet - used for searching ROM addresses.
 * @dev:	the master device
 * @bdir:	the bit to write if both id_bit and comp_bit are 0
 *
 * Return bits:
 *  bit 0 = id_bit
 *  bit 1 = comp_bit
 *  bit 2 = dir_taken
 *
 * If both bits 0 & 1 are set, the search should be restarted.
 *
 * Return:        bit fields - see above
 */
u8 w1_triplet(struct w1_master *dev, int bdir)
{
	if (dev->bus_master->triplet)
		return dev->bus_master->triplet(dev->bus_master->data, bdir);
	else {
		u8 id_bit   = w1_touch_bit(dev, 1);
		u8 comp_bit = w1_touch_bit(dev, 1);
		u8 retval;

		if (id_bit && comp_bit)
			return 0x03;  /* error */

		if (!id_bit && !comp_bit) {
			/* Both bits are valid, take the direction given */
			retval = bdir ? 0x04 : 0;
		} else {
			/* Only one bit is valid, take that direction */
			bdir = id_bit;
			retval = id_bit ? 0x05 : 0x02;
		}

		if (dev->bus_master->touch_bit)
			w1_touch_bit(dev, bdir);
		else
			w1_write_bit(dev, bdir);
		return retval;
	}
}
EXPORT_SYMBOL_GPL(w1_triplet);

/**
 * w1_read_8() - Reads 8 bits.
 * @dev:	the master device
 *
 * Return:        the byte read
 */
u8 w1_read_8(struct w1_master *dev)
{
	int i;
	u8 res = 0;

	if (dev->bus_master->read_byte)
		res = dev->bus_master->read_byte(dev->bus_master->data);
	else
		for (i = 0; i < 8; ++i)
			res |= (w1_touch_bit(dev,1) << i);

	//pr_info("W1 read byte: %02x\n", res); // print out the final result

	return res;
}
EXPORT_SYMBOL_GPL(w1_read_8);

/**
 * w1_write_block() - Writes a series of bytes.
 * @dev:	the master device
 * @buf:	pointer to the data to write
 * @len:	the number of bytes to write
 */
void w1_write_block(struct w1_master *dev, const u8 *buf, int len)
{
	int i;

	if (dev->bus_master->write_block) {
		w1_pre_write(dev);
		dev->bus_master->write_block(dev->bus_master->data, buf, len);
	}
	else
		for (i = 0; i < len; ++i)
			w1_write_8(dev, buf[i]); /* calls w1_pre_write */
	w1_post_write(dev);
}
EXPORT_SYMBOL_GPL(w1_write_block);

/**
 * w1_touch_block() - Touches a series of bytes.
 * @dev:	the master device
 * @buf:	pointer to the data to write
 * @len:	the number of bytes to write
 */
void w1_touch_block(struct w1_master *dev, u8 *buf, int len)
{
	int i, j;
	u8 tmp;

	for (i = 0; i < len; ++i) {
		tmp = 0;
		for (j = 0; j < 8; ++j) {
			if (j == 7)
				w1_pre_write(dev);
			tmp |= w1_touch_bit(dev, (buf[i] >> j) & 0x1) << j;
		}

		buf[i] = tmp;
	}
}
EXPORT_SYMBOL_GPL(w1_touch_block);

/**
 * w1_read_block() - Reads a series of bytes.
 * @dev:	the master device
 * @buf:	pointer to the buffer to fill
 * @len:	the number of bytes to read
 * Return:	the number of bytes read
 */
u8 w1_read_block(struct w1_master *dev, u8 *buf, int len)
{
	int i;
	u8 ret;
   	printk(KERN_DEBUG "read block started\n");

	if (dev->bus_master->read_block)
		ret = dev->bus_master->read_block(dev->bus_master->data, buf, len);
	else {
		for (i = 0; i < len; ++i)
			buf[i] = w1_read_8(dev);
		ret = len;
	}

	printk(KERN_DEBUG "read block complete\n");

	return ret;
}
EXPORT_SYMBOL_GPL(w1_read_block);

/**
 * w1_reset_bus() - Issues a reset bus sequence.
 * @dev:	the master device
 * Return:	0=Device present, 1=No device present or error
 */
int w1_reset_bus(struct w1_master *dev)
{
    int result;
    unsigned long flags = 0;
    ktime_t ts_write_bit_0 = 0, ts_write_bit_1 = 0, ts_read_bit_start = 0, ts_read_bit_end = 0;
    s64 read_bit_duration_ns;

    if (w1_disable_irqs)
        local_irq_save(flags);

    if (dev->bus_master->reset_bus) {
        result = dev->bus_master->reset_bus(dev->bus_master->data) & 0x1;
    } else {
        // Write_bit(0)
        w1_delay(dev, delay_values[6][dev->overdrive_mode_active]);
        dev->bus_master->write_bit(dev->bus_master->data, 0);
        ts_write_bit_0 = ktime_get();

        // Write_bit(1)
        w1_delay(dev, delay_values[7][dev->overdrive_mode_active]);
        dev->bus_master->write_bit(dev->bus_master->data, 1);
        ts_write_bit_1 = ktime_get();

        w1_delay(dev, delay_values[8][dev->overdrive_mode_active]);

        // Read_bit
        ts_read_bit_start = ktime_get();
        result = dev->bus_master->read_bit(dev->bus_master->data) & 0x1;
        ts_read_bit_end = ktime_get();

        w1_delay(dev, delay_values[9][dev->overdrive_mode_active]); // Delay after read_bit
    }

    // Switch to overdrive mode and perform reset if required
    if ((dev->bus_master->overdrive_mode == 1) && (dev->overdrive_mode_active == 0)) {
        w1_write_8(dev, W1_OD_SKIP_ROM);
        w1_delay(dev, 100); // Provide 100us of idle time before overdrive 1-Wire reset cycle.
        dev->overdrive_mode_active = 1;

        if (dev->bus_master->reset_bus) {
            result = dev->bus_master->reset_bus(dev->bus_master->data) & 0x1;
        } else {
            // Write_bit(0) in overdrive mode
            w1_delay(dev, delay_values[6][dev->overdrive_mode_active]);
            dev->bus_master->write_bit(dev->bus_master->data, 0);

            // Write_bit(1) in overdrive mode
            w1_delay(dev, delay_values[7][dev->overdrive_mode_active]);
            dev->bus_master->write_bit(dev->bus_master->data, 1);
            ts_write_bit_1 = ktime_get();

            w1_delay(dev, delay_values[8][dev->overdrive_mode_active]);

            // Read_bit in overdrive mode
            ts_read_bit_start = ktime_get();
            result = dev->bus_master->read_bit(dev->bus_master->data) & 0x1;
            ts_read_bit_end = ktime_get();

            w1_delay(dev, delay_values[9][dev->overdrive_mode_active]); // Delay after read_bit (overdrive mode)
        }
    }

    if (w1_disable_irqs)
        local_irq_restore(flags);

    // Calculate read_bit duration
    read_bit_duration_ns = ktime_to_ns(ktime_sub(ts_read_bit_end, ts_read_bit_start));

    // Print timestamps and result (example, adjust for your logging mechanism)
    printk(KERN_INFO "Timestamps: Write_bit(0): %lld ns, Write_bit(1): %lld ns, Read_bit start: %lld ns, Read_bit end: %lld ns\n",
           ktime_to_ns(ts_write_bit_0), ktime_to_ns(ts_write_bit_1), ktime_to_ns(ts_read_bit_start), ktime_to_ns(ts_read_bit_end));
    printk(KERN_INFO "Read_bit duration: %lld ns\n", read_bit_duration_ns);
    printk(KERN_INFO "Result: %d\n", result);

    return result;
}
EXPORT_SYMBOL_GPL(w1_reset_bus);

u8 w1_calc_crc8(u8 * data, int len)
{
	u8 crc = 0;

	while (len--)
		crc = w1_crc8_table[crc ^ *data++];

	return crc;
}
EXPORT_SYMBOL_GPL(w1_calc_crc8);

void w1_search_devices(struct w1_master *dev, u8 search_type, w1_slave_found_callback cb)
{
	printk(KERN_DEBUG "search devices called\n");
	dev->attempts++;
	if (dev->bus_master->search)
		dev->bus_master->search(dev->bus_master->data, dev,
			search_type, cb);
	else
		w1_search(dev, search_type, cb);
}

/**
 * w1_reset_select_slave() - reset and select a slave
 * @sl:		the slave to select
 *
 * Resets the bus and then selects the slave by sending either a skip rom
 * or a rom match.  A skip rom is issued if there is only one device
 * registered on the bus.
 * The w1 master lock must be held.
 *
 * Return:	0=success, anything else=error
 */
int w1_reset_select_slave(struct w1_slave *sl)
{
	u8 match[9] = {};
	printk(KERN_DEBUG "reset select slave called\n");

    if (w1_reset_bus(sl->master))
	    return -1;

    if (sl->master->slave_count == 1)
	{
	    if((sl->master->bus_master->overdrive_mode == 0) || (sl->master->overdrive_mode_active ==  1))
	    {
		    	w1_write_8(sl->master, W1_SKIP_ROM);
	    }
	    else if((sl->master->bus_master->overdrive_mode == 1) && (sl->master->overdrive_mode_active ==  0))
	    {
	    	w1_write_8(sl->master, W1_OD_SKIP_ROM);
			//After overdrive skip provide 100us of idle time before overdrive 1-Wire reset cycle.
    	    w1_delay(sl->master, 100);
	    	sl->master->overdrive_mode_active = 1;
        	w1_write_8(sl->master, W1_SKIP_ROM);
	    }
	}
	else {
	    if((sl->master->bus_master->overdrive_mode == 0) || (sl->master->overdrive_mode_active ==  1))
	    {
		    match[0] = W1_MATCH_ROM;
			u64 rn = le64_to_cpu(*((u64*)&sl->reg_num));

		    memcpy(&match[1], &rn, 8);
		    w1_write_block(sl->master, match, 9);
	    }
	    else if((sl->master->bus_master->overdrive_mode == 1) && (sl->master->overdrive_mode_active ==  0))
	    {
		    match[0] = W1_OD_MATCH_ROM;

			match[0] = W1_MATCH_ROM;
			u64 rn = le64_to_cpu(*((u64*)&sl->reg_num));

		    memcpy(&match[1], &rn, 8);
		    w1_write_block(sl->master, match, 9);

			match[0] = W1_MATCH_ROM;
			rn = le64_to_cpu(*((u64*)&sl->reg_num));

		    memcpy(&match[1], &rn, 8);
		    w1_write_block(sl->master, match, 9);
	    }

	}
	return 0;
}
EXPORT_SYMBOL_GPL(w1_reset_select_slave);

/**
 * w1_reset_resume_command() - resume instead of another match ROM
 * @dev:	the master device
 *
 * When the workflow with a slave amongst many requires several
 * successive commands a reset between each, this function is similar
 * to doing a reset then a match ROM for the last matched ROM. The
 * advantage being that the matched ROM step is skipped in favor of the
 * resume command. The slave must support the command of course.
 *
 * If the bus has only one slave, traditionnaly the match ROM is skipped
 * and a "SKIP ROM" is done for efficiency. On multi-slave busses, this
 * doesn't work of course, but the resume command is the next best thing.
 *
 * The w1 master lock must be held.
 */
int w1_reset_resume_command(struct w1_master *dev)
{
	if (w1_reset_bus(dev))
		return -1;

	w1_write_8(dev, dev->slave_count > 1 ? W1_RESUME_CMD : W1_SKIP_ROM);
	return 0;
}
EXPORT_SYMBOL_GPL(w1_reset_resume_command);

/**
 * w1_next_pullup() - register for a strong pullup
 * @dev:	the master device
 * @delay:	time in milliseconds
 *
 * Put out a strong pull-up of the specified duration after the next write
 * operation.  Not all hardware supports strong pullups.  Hardware that
 * doesn't support strong pullups will sleep for the given time after the
 * write operation without a strong pullup.  This is a one shot request for
 * the next write, specifying zero will clear a previous request.
 * The w1 master lock must be held.
 *
 * Return:	0=success, anything else=error
 */
void w1_next_pullup(struct w1_master *dev, int delay)
{
	dev->pullup_duration = delay;
}
EXPORT_SYMBOL_GPL(w1_next_pullup);
