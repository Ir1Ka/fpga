#ifndef __LINUX_FPGA_H
#define __LINUX_FPGA_H

#if defined(__KERNEL) || defined(__KERNEL__)
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/of.h>

#ifndef CONFIG_FPGA_CORE_VERSION
#define CONFIG_FPGA_CORE_VERSION	"v0.1.0"
#endif

#define FPGA_IP_NAME_SIZE		32
#define FPGA_IP_MODULE_PREFIX		"fpga-ip:"

extern struct bus_type fpga_bus_type;
extern struct device_type fpga_type;
extern struct device_type fpga_ip_type;

/* --- General options -------------------------------------------------------*/

struct fpga_algorithm;
struct fpga;
struct fpga_ip;
struct fpga_ip_driver;
struct fpga_ip_info;
union fpga_reg_data;
struct fpga_ip_id;

/* Read/Write a register. */
int fpga_reg_xfer(struct fpga *fpga, u64 addr, char rw, int size,
		  union fpga_reg_data *reg);
/* Same with @fpga_reg_xfer, but it needs to lock externally. */
int fpga_reg_xfer_locked(struct fpga *fpga, u64 addr, char rw, int size,
			 union fpga_reg_data *reg);

/* Read/Write a block. Refer to ``fpga_algorithm::block_xfer`` for return. */
int fpga_block_xfer(struct fpga *fpga, u64 addr, char rw, int size, u8 *block);
/* Same with @fpga_block_xfer, but it needs to lock externally. */
int fpga_block_xfer_locked(struct fpga *fpga, u64 addr, char rw, int size,
			   u8 *block);

#define FPGA_REG_RW_S(size, type)					\
int fpga_reg_read_ ## size (const struct fpga_ip *ip, int index,	\
			    u64 where, type *value);			\
int fpga_reg_write_ ## size (const struct fpga_ip *ip, int index,	\
			     u64 where, type value)

FPGA_REG_RW_S(byte, u8);
FPGA_REG_RW_S(word, u16);
FPGA_REG_RW_S(dword, u32);
FPGA_REG_RW_S(qword, u64);

/* Refer to ``fpga_algorithm::block_xfer`` for return. */
int fpga_read_block(const struct fpga_ip *ip, int index, u64 where, int size,
		    u8 *value);
/* Refer to ``fpga_algorithm::block_xfer`` for return. */
int fpga_write_block(const struct fpga_ip *ip, int index, u64 where, int size,
		     u8 *value);

/**
 * struct fpga_ip_driver - FPGA IP driver
 *
 * @id_table: List of FPGA IP supported by this driver
 * @probe: Callback for device binding
 * @remove: Callback for device unbinding
 * @shutdown: Callback for device shutdown
 * @suspend: Callback for device suspend
 * @resume: Callback for device resume
 * @driver: Device driver model driver
 * @ips: List of detected IPs we created (for fpga-core use only)
 */
struct fpga_ip_driver {
	const struct fpga_ip_id *id_table;

	int (*probe)(struct fpga_ip *, const struct fpga_ip_id *);
	int (*remove)(struct fpga_ip *);
	void (*shutdown)(struct fpga_ip *);
	int (*suspend)(struct fpga_ip *, pm_message_t);
	int (*resume)(struct fpga_ip *);

	struct device_driver driver;

	struct list_head ips;
};
#define to_fpga_ip_driver(_d) container_of(_d, struct fpga_ip_driver, driver)

struct fpga_ip_id {
	char name[FPGA_IP_NAME_SIZE];
	kernel_ulong_t driver_data	/* Data private to the driver */
			__attribute__((aligned(sizeof(kernel_ulong_t))));
};

/**
 * struct fpga_ip - structure for FPGA IP
 *
 * @name: name for display in /sys/bus/fpga/devices
 * @name: Indicates the type of the IP, usually a IP name that's generic enough
 *	to hide second-sourcing and compatiable revisions.
 * @fpga: manages the FPGA hosting the IP
 * @dev: device structure
 * @detected: member of an fpga_ip_driver.ips list or FPGA-core's
 *	userspace_ips list
 * @num_resources: number of resources
 * @resources: register addres ranges for the IP (mapped to top level FPGA)
 *
 * An fpga_ip identifies a single IP in an FPGA.
 */
struct fpga_ip {
	char name[FPGA_IP_NAME_SIZE];

	struct fpga *fpga;

	struct device dev;

	struct list_head detected;

	unsigned int num_resources;
	struct resource resources[0];
};
#define to_fpga_ip(_d) container_of(_d, struct fpga_ip, dev)

struct fpga_ip *fpga_verify_ip(struct device *dev);
struct fpga *fpga_verify(struct device *dev);
const struct fpga_ip_id *fpga_match_ip_id(const struct fpga_ip_id *ids,
					  const struct fpga_ip *ip);

static inline struct fpga_ip *kobj_to_fpga_ip(struct kobject *kobj)
{
	struct device * const dev = container_of(kobj, struct device, kobj);
	return to_fpga_ip(dev);
}

static inline void *fpga_get_ipdata(const struct fpga_ip *ip)
{
	return dev_get_drvdata(&ip->dev);
}

static inline void fpga_set_ipdata(struct fpga_ip *ip, void *data)
{
	dev_set_drvdata(&ip->dev, data);
}

static inline resource_size_t fpga_ip_first_addr(struct fpga_ip *ip)
{
	return ip->resources[0].start;
}

#endif /* __KERNEL */

#define FPGA_NUM_RESOURCES_MAX		4

#if defined(__KERNEL) || defined(__KERNEL__)

/**
 * struct fpga_ip_info - template for IP creation
 *
 * @type: chip type, to initialize fpga_ip.name
 * @dev_name: Overrides the default <fpganr>-<addr> dev_name of set
 * @platform_data: stored in fpga_ip.dev.platform_data
 * @of_node: pointor to OpenFirmware device node
 * @fwnode: device node supplied by the platform firmware
 * @properties: additional IP properties for the IP
 * @resources: resources associated with the IP.
 *	Up to ``FPGA_NUM_RESOURCES_MAX``, termination if resource size is 0.
 *
 * FPGA does not actually support IP probing, although FPGA can be represented
 * by certain flag registers.  Drivers commonly need more information than that,
 * such as IP type, associated resources, configuration, and so on.
 *
 * fpga_ip_info is used to build tables of information listing IPs that are
 * present, This information is used to grow the driver model tree.
 */
struct fpga_ip_info {
	char type[FPGA_IP_NAME_SIZE];
	const char *dev_name;
	void *platform_data;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	const struct property_entry *properties;
	unsigned int num_resources;
	struct resource resources[FPGA_NUM_RESOURCES_MAX];
};

#define FPGA_SIZE_RESOURCE_MAX		\
	(sizeof struct resource * FPGA_NUM_RESOURCES_MAX)

/* Must be check error code using IS_ERR(). */
struct fpga_ip *
__fpga_new_ip(struct fpga *fpga, struct fpga_ip_info const *info);
/* Wrapper of @__fpga_new_ip, return NULL if error. */
static inline struct fpga_ip *
fpga_new_ip(struct fpga *fpga, struct fpga_ip_info const *info)
{
	struct fpga_ip *ip = __fpga_new_ip(fpga, info);
	return IS_ERR(ip) ? NULL : ip;
}

void fpga_unregister_ip(struct fpga_ip *ip);

/**
 * struct fpga_algorithm - callback for transfer register (read/write)
 *
 * @reg_xfer: Issue single register transactions to the given FPGA.
 * 	Returns 0 if success, or a negative error code.
 * @block_xfer: Issue a block transactions to the given FPGA.
 * @functionality: Return the flags that this algorithm/FPGA pair supports
 *	from the ``FPGA_FUNC_*`` flags.
 *
 * In @reg_xfer, the @addr is an unified address. About unified address, please
 * refer to @fpga.
 */
struct fpga_algorithm {
	int (*reg_xfer)(struct fpga *fpga, u64 addr, char rw, int size,
			union fpga_reg_data *reg);
	/* Returns read/writen bytes or a negative error code. */
	int (*block_xfer)(struct fpga *fpga, u64 addr, char rw, int size,
			  u8 *block);

	/* To determine what the FPGA supports */
	u32 (*functionality)(struct fpga *fpga);
};

/* To determine what functionality is present */

#define FPGA_FUNC_READ_BYTE		0x00000001
#define FPGA_FUNC_WRITE_BYTE		0x00000002
#define FPGA_FUNC_READ_WORD		0x00000004
#define FPGA_FUNC_WRITE_WORD		0x00000008
#define FPGA_FUNC_READ_DWORD		0x00000010
#define FPGA_FUNC_WRITE_DWORD		0x00000020
#define FPGA_FUNC_READ_QWORD		0x00000040
#define FPGA_FUNC_WRITE_QWORD		0x00000080
#define FPGA_FUNC_READ_BLOCK		0x00010000
#define FPGA_FUNC_WRITE_BLOCK		0x00020000

#define FPGA_FUNC_BYTE			(FPGA_FUNC_READ_BYTE |		\
					 FPGA_FUNC_WRITE_BYTE)
#define FPGA_FUNC_WORD			(FPGA_FUNC_READ_WORD |		\
					 FPGA_FUNC_WRITE_WORD)
#define FPGA_FUNC_DWORD			(FPGA_FUNC_READ_DWORD |		\
					 FPGA_FUNC_WRITE_DWORD)
#define FPGA_FUNC_QWORD			(FPGA_FUNC_READ_QWORD |		\
					 FPGA_FUNC_WRITE_QWORD)
#define FPGA_FUNC_BLOCK			(FPGA_FUNC_READ_BLOCK |		\
					 FPGA_FUNC_WRITE_BLOCK)

/**
 * struct fpga - structure for FPGA
 *
 * @dev: device structure
 * @nr: id
 * @name: name for display in /sys/class/fpga
 * @addr_step: register address step size
 * @addr_step_shift: log2(@addr_step)
 * @reg_width: data width of each register
 * @reg_width_shift: log2(@reg_width)
 * @endian: data of register byte order
 * @algo: the opration to access the bus
 * @__reg: for direct access register from userspace
 * @__reg_lock: protect @__reg
 *
 * 1. Some FPGAs designed as a i2c, mdio or another device. Each of its
 *    register addresses can read or write multiple bytes.
 * 2. Some FPGAs designed as PCIe end point device. In terms of address design,
 *    it is similar to memory, but its register address must be aligned, such
 *    as 4 bytes aligned.
 * 3. Some FPGAs designed as big endian, but other little endian. Therefore,
 *    it is more appropriate to do endian conversion in the driver.
 *
 * NOTE: Based on the above discussion, for unified management, a unified
 * address access is designed here.
 */
struct fpga {
	struct module *owner;
	const struct fpga_algorithm *algo;
	void *algo_data;

	int timeout;
	int retries;
	struct device dev;

	int nr;
	char name[48];
	struct completion dev_released;

	struct mutex userspace_ips_lock;
	struct list_head userspace_ips;

	struct resource resource;

	int default_size;

	__u64 __addr;
	unsigned int __size;
	rwlock_t __rwlock;
};
#define to_fpga(_d) container_of(_d, struct fpga, dev)

static inline resource_size_t fpga_addr(struct fpga *fpga)
{
	return fpga->resource.start;
}

static inline void *fpga_get_data(const struct fpga *fpga)
{
	return dev_get_drvdata(&fpga->dev);
}

static inline void fpga_set_data(struct fpga *fpga, void *data)
{
	dev_set_drvdata(&fpga->dev, data);
}

static inline struct fpga *fpga_parent_is_fpga(const struct fpga *fpga)
{
	struct device *parent = fpga->dev.parent;

	if (parent != NULL && parent->type == &fpga_type)
		return to_fpga(parent);
	return NULL;
}

/* include for each IP and FPGA */
int fpga_for_each_dev(void *data, int (*fn)(struct device *dev, void *data));

#endif /* __KERNEL */

/**
 * union fpga_reg_data - union for store register value
 */
union fpga_reg_data {
	__u8 byte;
	__u16 word;
	__u32 dword;
	__u64 qword;
};

#define FPGA_BLOCK_SIZE_MAX	512

#define FPGA_READ	0
#define FPGA_WRITE	1

#if defined(__KERNEL) || defined(__KERNEL__)

int fpga_add(struct fpga *fpga);
void fpga_del(struct fpga *fpga);
int fpga_add_numbered(struct fpga *fpga);

int fpga_register_ip_driver(struct module *owner,
			    struct fpga_ip_driver *driver);
void fpga_del_ip_driver(struct fpga_ip_driver *driver);

/* se a define to avoid include chaining to get THIS_MODULE */
#define fpga_add_ip_driver(driver)					\
	fpga_register_ip_driver(THIS_MODULE, driver)

static inline bool fpga_ip_has_driver(struct fpga_ip *ip)
{
	return !IS_ERR_OR_NULL(ip) && ip->dev.driver;
}

struct fpga *fpga_get(int nr);
void fpga_put(struct fpga *fpga);
unsigned int fpga_depth(struct fpga *fpga);

static inline u32 fpga_get_functionality(struct fpga *fpga)
{
	return fpga->algo->functionality(fpga);
}

static inline int fpga_check_functionality(struct fpga *fpga, u32 func)
{
	return (func & fpga_get_functionality(fpga)) == func;
}

static inline int fpga_id(struct fpga *fpga)
{
	return fpga->nr;
}

#define module_fpga_ip_driver(__ip_driver)				\
	module_driver(__ip_driver, fpga_add_ip_driver, fpga_del_ip_driver)

#define builtin_fpga_ip_driver(__ip_driver)				\
	builtin_driver(__ip_driver, fpga_add_ip_driver)

#if IS_ENABLED(CONFIG_OF)

/* must call put_device(&ip->dev) when done with returned fpga IP */
struct fpga_ip *of_fpga_find_ip_by_node(struct device_node *node);

/* must call put_device(fpga->dev) when done with returned fpga */
struct fpga *of_fpga_find_by_node(struct device_node *node);

/* must call fpga_put(fpga) when done with returned fpga */
struct fpga *of_fpga_get_by_node(struct device_node *node);

const struct of_device_id *
of_fpga_match_ip_id(const struct of_device_id *matches, struct fpga_ip *ip);

int of_fpga_get_ip_info(struct device *dev, struct device_node *node,
			struct fpga_ip_info *info);

#else

static inline struct fpga_ip *of_fpga_find_ip_by_node(struct device_node *node)
{
	return NULL;
}

static inline struct fpga *of_fpga_find_by_node(struct device_node *node)
{
	return NULL;
}

static inline struct fpga *of_fpga_get_by_node(struct device_node *node)
{
	return NULL;
}

static inline const struct of_device_id *
of_fpga_match_ip_id(const struct of_device_id *matches, struct fpga_ip *ip)
{
	return NULL;
}

static inline int
of_fpga_get_ip_info(struct device *dev, struct device_node *node,
		    struct fpga_ip_info *info)
{
	return -ENOTSUPP;
}

#endif /* CONFIG_OF */

struct bits_attribute {
	struct device_attribute dev_attr;
	u16 off;
	u16 bits;
	bool flip;
	u64 where;
	int size;
};
#define to_bits_attr(_dev_attr)						\
	container_of(_dev_attr, struct bits_attribute, dev_attr)

#define BITS_ATTR(_name, _mode, _show, _store, _off, _bits, _flip,	\
		  _where, _size)					\
struct bits_attribute bits_attr_ ## _name = {				\
	.dev_attr = {							\
		.attr = {.name = __stringify(_name), .mode = _mode },	\
		.show   = _show,					\
		.store  = _store,					\
	},								\
	.off = _off,							\
	.bits = _bits,							\
	.flip = _flip,							\
	.where = _where,						\
	.size = _size,							\
}

#define BITS_ATTR_RW(_name, _off, _bits, _flip, _where, _size)		\
	BITS_ATTR(_name, S_IRUGO | S_IWUSR,				\
		  _name ## _show, _name ## _store,			\
		  _off, _bits, _flip, _where, _size)
#define BITS_ATTR_RO(_name, _off, _bits, _flip, _where, _size)		\
	BITS_ATTR(_name, S_IRUGO, _name ## _show, NULL,			\
		  _off, _bits, _flip, _where, _size)
#define BITS_ATTR_WO(_name, _off, _bits, _flip, _where, _size)		\
	BITS_ATTR(_name, S_IWUSR, NULL, _name ## _store,		\
		  _off, _bits, _flip, _where, _size)

#define BIT_ATTR_RW(_name, _off, _flip, _where, _size)			\
	BITS_ATTR_RW(_name, _off, 1, _flip, _where, _size)
#define BIT_ATTR_RO(_name, _off, _flip, _where, _size)			\
	BITS_ATTR_RO(_name, _off, 1, _flip, _where, _size)
#define BIT_ATTR_WO(_name, _off, _flip, _where, _size)			\
	BITS_ATTR_WO(_name, _off, 1, _flip, _where, _size)

ssize_t bits_attr_store(struct device *dev, struct device_attribute *attr,
			const char *buf, size_t count);
ssize_t bits_attr_show(struct device *dev, struct device_attribute *attr,
		       char *buf);

#define BITS_ATTR_RW_D(_name, _off, _bits, _flip, _where, _size)	\
	BITS_ATTR(_name, S_IRUGO | S_IWUSR,				\
		  bits_attr_show, bits_attr_store,			\
		  _off, _bits, _flip, _where, _size)
#define BITS_ATTR_RO_D(_name, _off, _bits, _flip, _where, _size)	\
	BITS_ATTR(_name, S_IRUGO, bits_attr_show, NULL,			\
		  _off, _bits, _flip, _where, _size)
#define BITS_ATTR_WO_D(_name, _off, _bits, _flip, _where, _size)	\
	BITS_ATTR(_name, S_IWUSR, NULL, bits_attr_store,		\
		  _off, _bits, _flip, _where, _size)

#define BIT_ATTR_RW_D(_name, _off, _flip, _where, _size)		\
	BITS_ATTR_RW_D(_name, _off, 1, _flip, _where, _size)
#define BIT_ATTR_RO_D(_name, _off, _flip, _where, _size)		\
	BITS_ATTR_RO_D(_name, _off, 1, _flip, _where, _size)
#define BIT_ATTR_WO_D(_name, _off, _flip, _where, _size)		\
	BITS_ATTR_WO_D(_name, _off, 1, _flip, _where, _size)

#endif /* __KERNEL */

#endif /* __LINUX_FPGA_H */
