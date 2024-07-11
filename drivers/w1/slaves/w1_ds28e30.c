#include <linux/module.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/w1.h>
#include <linux/types.h>
#include <linux/moduleparam.h>
#include <linux/ktime.h>

#include <linux/w1.h>


/** @brief Family code for DS28E30 */
#define W1_FAMILY_DS28E30		                 0x5B

/** @brief Size of public key in DS28E30 */
#define DS28E30_PUBLIC_KEY_SIZE                  64

/** @brief DS28E30 commands */
#define XPC_COMMAND                              0x66
#define CMD_WRITE_MEM                            0x96
#define CMD_READ_MEM                             0x44
#define CMD_READ_STATUS                          0xAA
#define CMD_SET_PAGE_PROT                        0xC3
#define CMD_COMP_READ_AUTH                       0xA5
#define CMD_DECREMENT_CNT                        0xC9
#define CMD_DISABLE_DEVICE                       0x33
#define CMD_READ_DEVICE_PUBLIC_KEY               0xCB
#define CMD_AUTHENTICATE_PUBLIC_KEY              0x59
#define CMD_AUTHENTICATE_WRITE                   0x89

/** @brief Test Mode sub-commands */
#define CMD_TM_ENABLE_DISABLE                    0xDD
#define CMD_TM_WRITE_BLOCK                       0xBB
#define CMD_TM_READ_BLOCK                        0x66

/** @brief Result bytes */
#define RESULT_SUCCESS                           0xAA
#define RESULT_FAIL_PROTECTION                   0x55
#define RESULT_FAIL_PARAMETETER                  0x77
#define RESULT_FAIL_INVALID_SEQUENCE             0x33
#define RESULT_FAIL_ECDSA                        0x22
#define RESULT_DEVICE_DISABLED	                 0x88
#define RESULT_FAIL_VERIFY                       0x00
#define RESULT_FAIL_COMMUNICATION                0xFF

/** @brief Pages */
#define PG_USER_EEPROM_0                         0
#define PG_USER_EEPROM_1                         1
#define PG_USER_EEPROM_2                         2
#define PG_USER_EEPROM_3                         3
#define PG_CERTIFICATE_R                         4
#define PG_CERTIFICATE_S                         5
#define PG_AUTHORITY_PUB_KEY_X                   6
#define PG_AUTHORITY_PUB_KEY_Y                   7
#define PG_DS28E30_PUB_KEY_X                     28
#define PG_DS28E30_PUB_KEY_Y                     29
#define PG_DS28E30_PRIVATE_KEY                   36
#define PG_DEC_COUNTER                           106

/** @brief Delays */
#define DELAY_DS28E30_EE_WRITE_TWM               100
#define DELAY_DS28E30_EE_READ_TRM                50
#define DELAY_DS28E30_ECDSA_GEN_TGES             200
#define DELAY_DS28E30_Verify_ECDSA_Signature_tEVS 200
#define DELAY_DS28E30_ECDSA_WRITE                350

/** @brief Protection bit fields */
#define PROT_RP                                  0x01  // Read Protection
#define PROT_WP                                  0x02  // Write Protection
#define PROT_EM                                  0x04  // EPROM Emulation Mode
#define PROT_DC                                  0x08  // Decrement Counter mode (only page 4)
#define PROT_AUTH                                0x20  // AUTH mode for authority public key X&Y
#define PROT_ECH                                 0x40  // Encrypted read and write using shared key from ECDH
#define PROT_ECW                                 0x80  // Authentication Write Protection ECDSA (not applicable to KEY_PAGES)

/** @brief Generate key flags */
#define ECDSA_KEY_LOCK                           0x80
#define ECDSA_USE_PUF                            0x01

/** @brief macros for bin attributes */
#define ROM_SIZE 32
#define MAN_ID_HWREV_SIZE 32 // Example size, adjust according to your needs
#define PROTECTION_PAGE0_SIZE 32 // the data is passed as string so each charecter is a byte
#define PRIVATE_KEY_SIZE 32 // the data is passed as string so each charecter is a byte
#define PUBLIC_KEY_PART_SIZE 32 // the data is passed as string so each charecter is a byte
#define DS28E30_PAGE_SIZE 32 // the data is passed as string so each charecter is a byte


// Global variable for last result byte (assuming it's defined somewhere in your context)
static u8 last_result_byte;
u8 rom_no[8];
u8 man_id[2];
u8 hardware_version[2];
unsigned short crc_16;
static u8 crc_8;
static short odd_parity[16] = { 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0 };


// keys in byte array format, used by software compute functions
u8 private_key[32];
u8 public_key_x[32];
u8 public_key_y[32];

//local static functions
static int w1_ds28e30_standard_cmd_flow(struct w1_slave *sl, u8 *write_buf, int write_len, int delay_ms, int expect_read_len, u8 *read_buf, int *read_len);

//--------------------------------------------------------------------------
// Calculate a new crc_16 from the input data shorteger.  Return the current
// crc_16 and also update the global variable crc_16.
//


unsigned short do_crc_16(unsigned short data)
{
   data = (data ^ (crc_16 & 0xff)) & 0xff;
   crc_16 >>= 8;

   if (odd_parity[data & 0xf] ^ odd_parity[data >> 4])
     crc_16 ^= 0xc001;

   data <<= 6;
   crc_16  ^= data;
   data <<= 1;
   crc_16   ^= data;

   return crc_16;
}

static unsigned char dscrc_table[] = {
        0, 94,188,226, 97, 63,221,131,194,156,126, 32,163,253, 31, 65,
      157,195, 33,127,252,162, 64, 30, 95,  1,227,189, 62, 96,130,220,
       35,125,159,193, 66, 28,254,160,225,191, 93,  3,128,222, 60, 98,
      190,224,  2, 92,223,129, 99, 61,124, 34,192,158, 29, 67,161,255,
       70, 24,250,164, 39,121,155,197,132,218, 56,102,229,187, 89,  7,
      219,133,103, 57,186,228,  6, 88, 25, 71,165,251,120, 38,196,154,
      101, 59,217,135,  4, 90,184,230,167,249, 27, 69,198,152,122, 36,
      248,166, 68, 26,153,199, 37,123, 58,100,134,216, 91,  5,231,185,
      140,210, 48,110,237,179, 81, 15, 78, 16,242,172, 47,113,147,205,
       17, 79,173,243,112, 46,204,146,211,141,111, 49,178,236, 14, 80,
      175,241, 19, 77,206,144,114, 44,109, 51,209,143, 12, 82,176,238,
       50,108,142,208, 83, 13,239,177,240,174, 76, 18,145,207, 45,115,
      202,148,118, 40,171,245, 23, 73,  8, 86,180,234,105, 55,213,139,
       87,  9,235,181, 54,104,138,212,149,203, 41,119,244,170, 72, 22,
      233,183, 85, 11,136,214, 52,106, 43,117,151,201, 74, 20,246,168,
      116, 42,200,150, 21, 75,169,247,182,232, 10, 84,215,137,107, 53};

//--------------------------------------------------------------------------
// Calculate the CRC8 of the byte value provided with the current
// global 'crc_8' value.
// Returns current global crc_8 value
//
unsigned char do_crc_8(unsigned char value)
{
   // See Application Note 27

   // TEST BUILD
   crc_8 = dscrc_table[crc_8 ^ value];
   return crc_8;
}

static int w1_ds28e30_standard_cmd_flow(struct w1_slave *sl, u8 *write_buf, int write_len, int delay_ms, int expect_read_len, u8 *read_buf, int *read_len) {
    u8 pkt[256];
    int pkt_len = 0;
    int i;

    mutex_lock(&sl->master->bus_mutex);

    // Reset/presence
    // Note: Assuming OWSkipROM() is a placeholder for a 1-Wire reset operation
    if (0 != w1_reset_select_slave(sl)) {
        return -1;
    }
    last_result_byte = RESULT_FAIL_COMMUNICATION;

    // Construct write block, start with XPC command
    pkt[pkt_len++] = XPC_COMMAND;

    // Add length
    pkt[pkt_len++] = write_len;

    // Write data buffer
    memcpy(&pkt[pkt_len], write_buf, write_len);
    pkt_len += write_len;

    // Send packet to DS28E30
    w1_write_block(sl->master, pkt, pkt_len); // Assuming NULL for dev because w1_write_block does not use dev parameter

    // Read two CRC bytes
    pkt[pkt_len++] = w1_read_8(sl->master);
    pkt[pkt_len++] = w1_read_8(sl->master);

    // Check crc_16
    crc_16 = 0;
    for (i = 0; i < pkt_len; i++) {
        do_crc_16(pkt[i]);
    }

    if (crc_16 != 0xB001) {
        return -1;
    }

    w1_next_pullup(sl->master, delay_ms);
    // Send release byte, start strong pull-up
    w1_write_8(sl->master, 0xAA);
    // Turn off strong pull-up
    // OWLevel(MODE_NORMAL); // Assuming this function controls the 1-Wire bus mode

    // Read FF and the length byte
    pkt[0] = w1_read_8(sl->master);
    pkt[1] = w1_read_8(sl->master);
    *read_len = pkt[1];

    // Ensure there is a valid length
    if (*read_len != RESULT_FAIL_COMMUNICATION) {
        // Read packet
        w1_read_block(sl->master, read_buf, *read_len + 2);

        // Check crc_16
        crc_16 = 0;
        do_crc_16(*read_len);
        for (i = 0; i < (*read_len + 2); i++) {
            do_crc_16(read_buf[i]);
        }

        if (crc_16 != 0xB001) {
            return -1;
        }

        if (expect_read_len != *read_len) {
            return -1;
        }
    } else {
        return -1;
    }

   	mutex_unlock(&sl->master->bus_mutex);

    // Success
    return 0;
}

int w1_ds28e30_cmd_writeMemory(struct w1_slave *sl, int pg, u8 *data)
{
   u8 write_buf[50];
   int write_len;
   u8 read_buf[255];
   int read_len;

   /*
     Reset
     Presence Pulse
     <ROM Select>
   TX: XPC Command (66h)
   TX: Length byte 34d
   TX: XPC sub-command 96h (Write Memory)
   TX: Parameter
   TX: New page data (32d bytes)
   RX: CRC16 (inverted of XPC command, length, sub-command, parameter)
   TX: Release Byte
     <Delay TBD>
   RX: Dummy Byte
   RX: Length Byte (1d)
   RX: Result Byte
   RX: CRC16 (inverted of length and result byte)
     Reset or send XPC command (66h) for a new sequence
   */

   // construct the write buffer
   write_len = 0;
   write_buf[write_len++] = CMD_WRITE_MEM;
   write_buf[write_len++] = pg;
   memcpy(&write_buf[write_len], data, 32);
   write_len += 32;

   // preload read_len with expected length
   read_len = 1;

   // default failure mode
   last_result_byte = RESULT_FAIL_COMMUNICATION;

   if (0 == w1_ds28e30_standard_cmd_flow(sl, write_buf, write_len,  DELAY_DS28E30_EE_WRITE_TWM, read_len, read_buf, &read_len))
   {
      // get result byte
      last_result_byte = read_buf[0];
      // check result
      if (read_len == 1)
         return !(read_buf[0] == RESULT_SUCCESS);
   }

   // no payload in read buffer or failed command
   return -1;
}

int ds28e30_cmd_readMemory(struct w1_slave *sl, int pg, u8 *data)
{
   u8 write_buf[10];
   int write_len;
   u8 read_buf[255];
   int read_len;

   /*
     Reset
     Presence Pulse
     <ROM Select>
   TX: XPC Command (66h)
   TX: Length byte 2d
   TX: XPC sub-command 69h (Read Memory)
   TX: Parameter (page)
   RX: CRC16 (inverted of XPC command, length, sub-command, and parameter)
   TX: Release Byte
     <Delay TBD>
   RX: Dummy Byte
   RX: Length (33d)
   RX: Result Byte
   RX: Read page data (32d bytes)
   RX: CRC16 (inverted, length byte, result byte, and page data)
     Reset or send XPC command (66h) for a new sequence
   */

   // construct the write buffer
   write_len = 0;
   write_buf[write_len++] = CMD_READ_MEM;
   write_buf[write_len++] = pg;

   // preload read_len with expected length
   read_len = 33;

   // default failure mode
   last_result_byte = RESULT_FAIL_COMMUNICATION;

   if (0 == w1_ds28e30_standard_cmd_flow(sl, write_buf, write_len,  DELAY_DS28E30_EE_READ_TRM, read_len, read_buf, &read_len))
   {
      // get result byte
      last_result_byte = read_buf[0];
      // check result
      if (read_len == 33)
      {
         if (read_buf[0] == RESULT_SUCCESS)
         {
            memcpy(data, &read_buf[1], 32);
            return 0;
         }
      }
   }

   // no payload in read buffer or failed command
   return -1;
}

int w1_ds28e30_cmd_readStatus(struct w1_slave *sl, int pg, u8 *pr_data, u8 *man_id, u8 *hardware_version) {
   u8 write_buf[10];
   u8 read_buf[255];
   int read_len=2, write_len;

   /*
     Reset
     Presence Pulse
     <ROM Select>
   TX: XPC Command (66h)
   TX: Length byte 1d
   TX: XPC sub-command AAh (Read Status)
   RX: crc_16 (inverted of XPC command, length, and sub-command)
   TX: Release Byte
     <Delay TBD>
   RX: Dummy Byte
   RX: Length Byte (11d)
   RX: Result Byte
   RX: Read protection values (6 Bytes), MANID (2 Bytes), ROM VERSION (2 bytes)
   RX: crc_16 (inverted, length byte, protection values, MANID, ROM_VERSION)
     Reset or send XPC command (66h) for a new sequence
   */

   // construct the write buffer
   write_len = 0;
   write_buf[write_len++] = CMD_READ_STATUS;
   write_buf[write_len++] = pg;

   // preload read_len with expected length
   if (pg & 0x80) read_len = 5;

   // default failure mode
   last_result_byte = RESULT_FAIL_COMMUNICATION;

 //   return w1_ds28e30_standard_cmd_flow(write_buf, write_len,  DELAY_DS28E30_EE_READ_TRM, read_len, read_buf, &read_len);  //?????

   if (0 == w1_ds28e30_standard_cmd_flow(sl, write_buf, write_len,  DELAY_DS28E30_EE_READ_TRM, read_len, read_buf, &read_len))
   {
      // get result byte
      last_result_byte = read_buf[0];
      // should always be 2 or 5 length for status data
      if (read_len == 2 || read_len == 5)
      {
         if (read_buf[0] == RESULT_SUCCESS || read_buf[0]== RESULT_DEVICE_DISABLED )
         {
            if( read_len == 2 ) memcpy(pr_data, &read_buf[1], 1);
            else
            {
              memcpy(man_id, &read_buf[1], 2);
              memcpy(hardware_version, &read_buf[3], 2);
            }
            return 0;
         }
      }
   }

   // no payload in read buffer or failed command
   return -1;
}

static ssize_t rom_read(struct file *filp, struct kobject *kobj,
                        struct bin_attribute *bin_attr, char *buf,
                        loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 i;
    ssize_t ret = 0;

    if (off != 0 || count < 17) { // Ensure enough space for 16 bytes (2 hex digits per byte + 1 space)
        return 0; // Return 0 to signify end of file or no data read
    }
    if (!buf) {
        return -EINVAL; // Invalid argument
    }

    memset(rom_no, 0, sizeof(rom_no));

    if (w1_reset_bus(sl->master) == 0) {

        w1_write_8(sl->master, 0x33); // Read ROM command
        for (i = 0; i < 8; i++) {
            rom_no[i] = w1_read_8(sl->master);
        }

        // Format ROM data into a hexadecimal string with spaces
        ret = snprintf(buf, count, "%02x %02x %02x %02x %02x %02x %02x %02x\n",
                       rom_no[0], rom_no[1], rom_no[2], rom_no[3],
                       rom_no[4], rom_no[5], rom_no[6], rom_no[7]);

        if (ret < 0 || ret >= count) {
            ret = -EFAULT; // Error formatting data
        } else {
        }
    } else {
        ret = -EIO; // I/O error
    }

    return ret;
}

static ssize_t man_id_hwrev_read(struct file *filp, struct kobject *kobj,
                                 struct bin_attribute *bin_attr, char *buf,
                                 loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 protection_byte;
    int ret;
    int len = 0;


    if (off != 0) {
        return 0;
    }
    if (!buf) {
        return -EINVAL;
    }

    // Call the w1_ds28e30_cmd_readStatus function
    ret = w1_ds28e30_cmd_readStatus(sl, 0x80 | 0, &protection_byte, man_id, hardware_version);  // page number=0
    if (ret < 0) {
        len = sprintf(buf, "Error reading MANID and Hardware Revision: %d\n", ret);
        return len;  // Return the number of bytes written to buf
    }

    // Print the MANID and hardware_version to the buffer
    len = sprintf(buf, "MANID: 0x%02x%02x, Hardware Version: 0x%02x%02x\n",
                  man_id[0], man_id[1], hardware_version[0], hardware_version[1]);

    // Return the number of bytes written to buf
    return len;
}



static ssize_t protection_page0_read(struct file *filp, struct kobject *kobj,
                                     struct bin_attribute *bin_attr, char *buf,
                                     loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 protection_byte;
    int ret;
    int len = 0;

    if (off != 0)
        return 0;
    if (!buf)
        return -EINVAL;

    // Call the w1_ds28e30_cmd_readStatus function
    ret = w1_ds28e30_cmd_readStatus(sl, 0, &protection_byte, man_id, hardware_version);  // page number=0
    if (ret < 0) {
        len = sprintf(buf, "Error reading status: %d\n", ret);
        return len;  // Return the number of bytes written to buf
    }

    // Print the protection byte to the buffer
    len = sprintf(buf, "Protection Byte: 0x%02x\n", protection_byte);

    // Return the number of bytes written to buf
    return len;
}

// Function to write private key
static ssize_t private_key_write(struct file *filp, struct kobject *kobj,
                                 struct bin_attribute *bin_attr, char *buf,
                                 loff_t off, size_t count)
{
    int i;

    if (off != 0 || count != PRIVATE_KEY_SIZE) { // Ensure write is for the full 64 characters (32 bytes)
        return -EINVAL; // Invalid argument
    }
    if (!buf) {
        return -EINVAL; // Invalid argument
    }

    // Copy the data directly
    memcpy(private_key, buf, PRIVATE_KEY_SIZE);


    // Print out the private key in hexadecimal format
    for (i = 0; i < PRIVATE_KEY_SIZE; i++) {
        pr_cont("%02x ", private_key[i]);
    }
    pr_cont("\n");

    return count; // Return number of bytes written (should be 64 for 32 bytes of hex input)
}

// Write function for public key X part
static ssize_t public_key_x_write(struct file *filp, struct kobject *kobj,
                                  struct bin_attribute *bin_attr, char *buf,
                                  loff_t off, size_t count)
{
    // Verify offset and count
    if (off != 0 || count != PUBLIC_KEY_PART_SIZE) {
        return -EINVAL; // Invalid argument
    }
    // Verify buffer pointer
    if (!buf) {
        return -EINVAL; // Invalid argument
    }

    // Copy the data directly
    memcpy(public_key_x, buf, PUBLIC_KEY_PART_SIZE);

    return count; // Return number of bytes written
}

// Write function for public key Y part
static ssize_t public_key_y_write(struct file *filp, struct kobject *kobj,
                                  struct bin_attribute *bin_attr, char *buf,
                                  loff_t off, size_t count)
{
    // Verify offset and count
    if (off != 0 || count != PUBLIC_KEY_PART_SIZE) {
        return -EINVAL; // Invalid argument
    }
    // Verify buffer pointer
    if (!buf) {
        return -EINVAL; // Invalid argument
    }

    // Copy the data directly
    memcpy(public_key_y, buf, DS28E30_PAGE_SIZE);

    return count; // Return number of bytes written
}

static ssize_t page0_write(struct file *filp, struct kobject *kobj,
                           struct bin_attribute *bin_attr, char *buf,
                           loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 page0_data[DS28E30_PAGE_SIZE];  // Assuming DS28E30_PAGE_SIZE is defined elsewhere
    int ret;

    if (off != 0 || count != DS28E30_PAGE_SIZE) {
        return -EINVAL;
    }
    if (!buf) {
        return -EINVAL;
    }

    // Copy the data directly from user buffer
    memcpy(page0_data, buf, DS28E30_PAGE_SIZE);

    // Write page 0 data using w1_ds28e30_cmd_writeMemory
    ret = w1_ds28e30_cmd_writeMemory(sl, 0, page0_data); // Page number 0
    if (ret < 0) {
        return ret;
    }

    return count; // Return number of bytes written
}


static ssize_t page0_read(struct file *filp, struct kobject *kobj,
                          struct bin_attribute *bin_attr, char *buf,
                          loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 page0_data[DS28E30_PAGE_SIZE];  // Statically allocated buffer
    int ret;

    if (off != 0) {
        return 0; // Only allow reads from the beginning
    }

    if (!buf) {
        return -EINVAL; // Null buffer pointer
    }
    if (count > DS28E30_PAGE_SIZE) {
        return -EINVAL; // Invalid count size
    }

    // Read page 0 data using ds28e30_cmd_readMemory
    ret = ds28e30_cmd_readMemory(sl, 0, page0_data); // Page number 0
    if (ret < 0) {
        return ret; // Return error code directly
    }

    memcpy(buf, page0_data, sizeof(page0_data)/page0_data[0]);

    return count; // Return number of bytes read
}

static ssize_t page1_write(struct file *filp, struct kobject *kobj,
                           struct bin_attribute *bin_attr, char *buf,
                           loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 page0_data[DS28E30_PAGE_SIZE];  // Assuming DS28E30_PAGE_SIZE is defined elsewhere
    int ret;

    if (off != 0 || count != DS28E30_PAGE_SIZE) {
        return -EINVAL;
    }
    if (!buf) {
        return -EINVAL;
    }

    // Copy the data directly from user buffer
    memcpy(page0_data, buf, DS28E30_PAGE_SIZE);

    // Write page 0 data using w1_ds28e30_cmd_writeMemory
    ret = w1_ds28e30_cmd_writeMemory(sl, 1, page0_data); // Page number 0
    if (ret < 0) {
        return ret;
    }

    return count; // Return number of bytes written
}


static ssize_t page1_read(struct file *filp, struct kobject *kobj,
                          struct bin_attribute *bin_attr, char *buf,
                          loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 page0_data[DS28E30_PAGE_SIZE];  // Statically allocated buffer
    int ret;

    if (off != 0) {
        return 0; // Only allow reads from the beginning
    }

    if (!buf) {
        return -EINVAL; // Null buffer pointer
    }
    if (count > DS28E30_PAGE_SIZE) {
        return -EINVAL; // Invalid count size
    }

    // Read page 0 data using ds28e30_cmd_readMemory
    ret = ds28e30_cmd_readMemory(sl, 1, page0_data); // Page number 0
    if (ret < 0) {
        return ret; // Return error code directly
    }

    memcpy(buf, page0_data, sizeof(page0_data)/page0_data[0]);

    return count; // Return number of bytes read
}

static ssize_t page2_write(struct file *filp, struct kobject *kobj,
                           struct bin_attribute *bin_attr, char *buf,
                           loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 page0_data[DS28E30_PAGE_SIZE];  // Assuming DS28E30_PAGE_SIZE is defined elsewhere
    int ret;

    if (off != 0 || count != DS28E30_PAGE_SIZE) {
        return -EINVAL;
    }
    if (!buf) {
        return -EINVAL;
    }

    // Copy the data directly from user buffer
    memcpy(page0_data, buf, DS28E30_PAGE_SIZE);

    // Write page 0 data using w1_ds28e30_cmd_writeMemory
    ret = w1_ds28e30_cmd_writeMemory(sl, 2, page0_data); // Page number 0
    if (ret < 0) {
        return ret;
    }

    return count; // Return number of bytes written
}


static ssize_t page2_read(struct file *filp, struct kobject *kobj,
                          struct bin_attribute *bin_attr, char *buf,
                          loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 page0_data[DS28E30_PAGE_SIZE];  // Statically allocated buffer
    int ret;

    if (off != 0) {
        return 0; // Only allow reads from the beginning
    }

    if (!buf) {
        return -EINVAL; // Null buffer pointer
    }
    if (count > DS28E30_PAGE_SIZE) {
        return -EINVAL; // Invalid count size
    }

    // Read page 0 data using ds28e30_cmd_readMemory
    ret = ds28e30_cmd_readMemory(sl, 2, page0_data); // Page number 0
    if (ret < 0) {
        return ret; // Return error code directly
    }

    memcpy(buf, page0_data, sizeof(page0_data)/page0_data[0]);

    return count; // Return number of bytes read
}

static ssize_t page3_write(struct file *filp, struct kobject *kobj,
                           struct bin_attribute *bin_attr, char *buf,
                           loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 page0_data[DS28E30_PAGE_SIZE];  // Assuming DS28E30_PAGE_SIZE is defined elsewhere
    int ret;

    if (off != 0 || count != DS28E30_PAGE_SIZE) {
        return -EINVAL;
    }
    if (!buf) {
        return -EINVAL;
    }

    // Copy the data directly from user buffer
    memcpy(page0_data, buf, DS28E30_PAGE_SIZE);

    // Write page 0 data using w1_ds28e30_cmd_writeMemory
    ret = w1_ds28e30_cmd_writeMemory(sl, 3, page0_data); // Page number 0
    if (ret < 0) {
        return ret;
    }

    return count; // Return number of bytes written
}


static ssize_t page3_read(struct file *filp, struct kobject *kobj,
                          struct bin_attribute *bin_attr, char *buf,
                          loff_t off, size_t count)
{
    struct w1_slave *sl = kobj_to_w1_slave(kobj);
    u8 page0_data[DS28E30_PAGE_SIZE];  // Statically allocated buffer
    int ret;

    if (off != 0) {
        return 0; // Only allow reads from the beginning
    }

    if (!buf) {
        return -EINVAL; // Null buffer pointer
    }
    if (count > DS28E30_PAGE_SIZE) {
        return -EINVAL; // Invalid count size
    }

    // Read page 0 data using ds28e30_cmd_readMemory
    ret = ds28e30_cmd_readMemory(sl, 3, page0_data); // Page number 0
    if (ret < 0) {
        return ret; // Return error code directly
    }

    memcpy(buf, page0_data, sizeof(page0_data)/page0_data[0]);

    return count; // Return number of bytes read
}
// Define Binary Attributes
static BIN_ATTR_RO(rom, ROM_SIZE);
static BIN_ATTR_RO(man_id_hwrev, MAN_ID_HWREV_SIZE);
static BIN_ATTR_RO(protection_page0, PROTECTION_PAGE0_SIZE);
static BIN_ATTR_WO(private_key, PRIVATE_KEY_SIZE);
static BIN_ATTR_WO(public_key_x, PUBLIC_KEY_PART_SIZE);
static BIN_ATTR_WO(public_key_y, PUBLIC_KEY_PART_SIZE);
static BIN_ATTR_RW(page0, DS28E30_PAGE_SIZE);
static BIN_ATTR_RW(page1, DS28E30_PAGE_SIZE);
static BIN_ATTR_RW(page2, DS28E30_PAGE_SIZE);
static BIN_ATTR_RW(page3, DS28E30_PAGE_SIZE);

// Attribute Group
static struct bin_attribute *w1_ds28e30_bin_attrs[] = {
    &bin_attr_rom,
    &bin_attr_man_id_hwrev,
    &bin_attr_protection_page0,
    &bin_attr_private_key,
    &bin_attr_public_key_x,
    &bin_attr_public_key_y,
    &bin_attr_page0,
    &bin_attr_page1,
    &bin_attr_page2,
    &bin_attr_page3,
    NULL,
};

static const struct attribute_group w1_ds28e30_group = {
    .bin_attrs = w1_ds28e30_bin_attrs,
};

static const struct attribute_group *w1_ds28e30_groups[] = {
    &w1_ds28e30_group,
    NULL,
};

// Family Operations
static const struct w1_family_ops w1_ds28e30_fops = {
    .groups = w1_ds28e30_groups,
};

// Family Definition
static struct w1_family w1_ds28e30_family = {
    .fid = W1_FAMILY_DS28E30, // Define your family ID, e.g., 0x30
    .fops = &w1_ds28e30_fops,
};

// Register Module
module_w1_family(w1_ds28e30_family);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name <manoj.rajashekaraiah@analog.com>");
MODULE_DESCRIPTION("1-wire driver for Maxim/Dallas DS28E30 Secure Authenticator");
MODULE_ALIAS("w1-family-" __stringify(W1_FAMILY_DS28E30));