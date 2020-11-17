#ifndef __LINUX_FPGA_H
#define __LINUX_FPGA_H

#if defined(__KERNEL) || defined(__KERNEL__)
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/err.h>

#define MAX_LOCKDEP_SUBCLASSES		8UL

#ifndef CONFIG_FPGA_CORE_VERSION
#define CONFIG_FPGA_CORE_VERSION	"v0.1.1"
#endif

#define FPGA_IP_NAME_SIZE		32
#define FPGA_IP_MODULE_PREFIX		"fpga-ip:"

extern struct bus_type fpga_bus_type;
extern struct device_type fpga_type;
extern struct device_type fpga_ip_type;

/* --- General options -------------------------------------------------------*/

typedef u8  byte;
typedef u16 word;
typedef u32 dword;
typedef u64 qword;

struct fpga_operations;
struct fpga;
struct fpga_ip;
struct fpga_ip_driver;
struct fpga_ip_info;
struct fpga_ip_id;

/* ----- REG and block access interface through fpga ----- */

int fpga_read8(struct fpga *fpga, u64 addr, u8 *value);
int fpga_write8(struct fpga *fpga, u64 addr, u8 value);

int fpga_read16(struct fpga *fpga, u64 addr, u16 *value);
int fpga_write16(struct fpga *fpga, u64 addr, u16 value);

int fpga_read32(struct fpga *fpga, u64 addr, u32 *value);
int fpga_write32(struct fpga *fpga, u64 addr, u32 value);

int fpga_read64(struct fpga *fpga, u64 addr, u64 *value);
int fpga_write64(struct fpga *fpga, u64 addr, u64 value);

ssize_t fpga_read_block(struct fpga *fpga, u64 addr, size_t size, u8 *block);
ssize_t fpga_write_block(struct fpga *fpga, u64 addr, size_t size, u8 *block);

/* ----- REG and block access interface through ip ----- */

int fpga_ip_read8(struct fpga_ip *ip, int idx, u64 where, u8 *value);
int fpga_ip_write8(struct fpga_ip *ip, int idx, u64 where, u8 value);

int fpga_ip_read16(struct fpga_ip *ip, int idx, u64 where, u16 *value);
int fpga_ip_write16(struct fpga_ip *ip, int idx, u64 where, u16 value);

int fpga_ip_read32(struct fpga_ip *ip, int idx, u64 where, u32 *value);
int fpga_ip_write32(struct fpga_ip *ip, int idx, u64 where, u32 value);

int fpga_ip_rea64(struct fpga_ip *ip, int idx, u64 where, u64 *value);
int fpga_ip_write64(struct fpga_ip *ip, int idx, u64 where, u64 value);

ssize_t fpga_ip_read_block(struct fpga_ip *ip, int index, u64 where, size_t size, u8 *value);
ssize_t fpga_ip_write_block(struct fpga_ip *ip, int index, u64 where, size_t size, u8 *value);

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

/*
 * For @vp, some resource if mappable, therefore, map it and store into @vp for
 * bypass the register and block access interface to speed up the access speed.
 *
 * NOTE: visitors need to deal with restrictions such as alignment, size and etc.
 */
struct fpga_resource {
	struct resource resource;
	void __iomem *vp;
};

static inline int check_fpga_addr(const struct fpga_resource *r, u64 addr, int size)
{
	int valid;

	valid = ((addr >= r->resource.start) &&
		 ((addr + size) <= (r->resource.end + 1)));
	return likely(valid) ? 0 : -EFAULT;
}

/**
 * struct fpga_ip - structure for FPGA IP
 *
 * @name: name of FPGA IP
 * @fpga: FPGA chip to which the IP belongs
 * @dev: device structure
 * @detected: member of an `fpga_ip_driver::ips` or `fpga::userspace_ips` list
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
	struct fpga_resource resources[0];
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
	return ip->resources[0].resource.start;
}

#endif /* __KERNEL */

#if defined(__KERNEL) || defined(__KERNEL__)

/**
 * struct fpga_ip_info - template for IP creation
 *
 * @type: chip type, to initialize `fpga_ip::name`
 * @dev_name: Overrides the default <fpga_id>-<addr> dev_name of set
 * @platform_data: stored in `fpga_ip::dev::platform_data`
 * @of_node: pointor to OpenFirmware device node
 * @fwnode: device node supplied by the platform firmware
 * @properties: additional IP properties for the IP
 * @num_resources: number of resources
 * @resources: register addres ranges for the IP (mapped to top level FPGA)
 *
 * FPGA does not actually support IP probing, although FPGA can be represented
 * by certain flag registers.  Drivers commonly need more information than that,
 * such as IP type, associated resources, configuration, and so on.
 *
 * fpga_ip_info is used to build tables of information listing IPs that are
 * present, This information is used to grow the driver model tree.
 *
 * NOTE: The structure need alloc by `fpga_alloc_ip_info` and free by `fpga_free_ip_info`.
 */
struct fpga_ip_info {
	char type[FPGA_IP_NAME_SIZE];
	const char *dev_name;
	void *platform_data;
	struct device_node *of_node;
	const struct property_entry *properties;
	unsigned int num_resources;
	struct fpga_resource resources[0];
};

struct fpga_ip_info *fpga_alloc_ip_info(const char *type, unsigned int num_resources, gfp_t flags);
void fpga_free_ip_info(struct fpga_ip_info *info);

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
 * struct fpga_operations - callback for transfer register (read/write)
 *
 * @read8/@write8: Access a byte register.
 * @read16/@write16: Access a word register.
 * @read32/@write32: Access a dword register.
 * @read64/@write64: Access a qword register.
 * @read_block/@write_block: Access block.
 * @functionality: Return the flags that this operations/FPGA pair supports
 *	from the `FPGA_FUNC_*` flags.
 *
 * The register access interface return 0 if success, or a negative error code.
 * The block access interface return read/wroten bytes number, or a negative error code.
 * The @addr is an unified address.
 */
struct fpga_operations {
	int (*read8)(struct fpga *fpga, u64 addr, u8 *reg);
	int (*write8)(struct fpga *fpga, u64 addr, u8 reg);

	int (*read16)(struct fpga *fpga, u64 addr, u16 *reg);
	int (*write16)(struct fpga *fpga, u64 addr, u16 reg);

	int (*read32)(struct fpga *fpga, u64 addr, u32 *reg);
	int (*write32)(struct fpga *fpga, u64 addr, u32 reg);

	int (*read64)(struct fpga *fpga, u64 addr, u64 *reg);
	int (*write64)(struct fpga *fpga, u64 addr, u64 reg);

	/* Returns read/writen bytes or a negative error code. */
	ssize_t (*read_block)(struct fpga *fpga, u64 addr, size_t size, u8 *block);
	ssize_t (*write_block)(struct fpga *fpga, u64 addr, size_t size, u8 *block);

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
#define FPGA_FUNC_DIRECT		0x00040000

#define FPGA_FUNC_BYTE		(FPGA_FUNC_READ_BYTE | FPGA_FUNC_WRITE_BYTE)
#define FPGA_FUNC_WORD		(FPGA_FUNC_READ_WORD | FPGA_FUNC_WRITE_WORD)
#define FPGA_FUNC_DWORD		(FPGA_FUNC_READ_DWORD | FPGA_FUNC_WRITE_DWORD)
#define FPGA_FUNC_QWORD		(FPGA_FUNC_READ_QWORD | FPGA_FUNC_WRITE_QWORD)
#define FPGA_FUNC_BLOCK		(FPGA_FUNC_READ_BLOCK | FPGA_FUNC_WRITE_BLOCK)

/**
 * struct fpga - structure for FPGA
 *
 * @owner: owner of the FPGA device
 * @ops: the operation to access the FPGA
 * @ops_data: data of ops to use
 * @timeout: transfer timeout by jiffies
 * @retries: number of revisit attempts
 * @dev: device structure
 * @nr: id
 * @name: name of FPGA
 * @dev_released: for del FPGA
 * @userspace_ips_lock: lock for @userspace_ips
 * @userspace_ips: store the created IP through `new_ip` attribute
 * @resource: address resource of FPGA described by `struct resource`
 * @__addr: address for direct access register from user space
 * @__block_size: block size for direct access block from user space
 * @__rwlock: protect @__addr and @__block_size
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
 *       address access is designed here.
 */
struct fpga {
	struct module *owner;
	const struct fpga_operations *ops;
	void *ops_data;

	int timeout;
	int retries;
	struct device dev;

	int nr;
	char name[48];
	struct completion dev_released;

	struct mutex userspace_ips_lock;
	struct list_head userspace_ips;

	struct fpga_resource resource;

	__u64 __addr;
	size_t __block_size;
	rwlock_t __rwlock;
};
#define to_fpga(_d) container_of(_d, struct fpga, dev)

static inline resource_size_t fpga_addr(struct fpga *fpga)
{
	return fpga->resource.resource.start;
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

#define FPGA_BLOCK_SIZE_MAX	512

#if defined(__KERNEL) || defined(__KERNEL__)

int fpga_add(struct fpga *fpga);
void fpga_del(struct fpga *fpga);
int fpga_add_numbered(struct fpga *fpga);

int fpga_register_ip_driver(struct module *owner,
			    struct fpga_ip_driver *driver);
void fpga_del_ip_driver(struct fpga_ip_driver *driver);

/* a define to avoid include chaining to get THIS_MODULE */
#define fpga_add_ip_driver(driver)	\
	fpga_register_ip_driver(THIS_MODULE, driver)

static inline bool fpga_ip_has_driver(struct fpga_ip *ip)
{
	return !(unlikely(!ip) || IS_ERR(ip)) && ip->dev.driver;
}

struct fpga *fpga_get(int nr);
void fpga_put(struct fpga *fpga);
unsigned int fpga_depth(struct fpga *fpga);

static inline u32 fpga_get_functionality(struct fpga *fpga)
{
	return fpga->ops->functionality(fpga);
}

static inline int fpga_check_functionality(struct fpga *fpga, u32 func)
{
	return (func & fpga_get_functionality(fpga)) == func;
}

static inline int fpga_id(struct fpga *fpga)
{
	return fpga->nr;
}

#define module_fpga_ip_driver(__ip_driver)	\
	module_driver(__ip_driver, fpga_add_ip_driver, fpga_del_ip_driver)

#define builtin_fpga_ip_driver(__ip_driver)	\
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
			struct fpga_ip_info **infop);

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
		    struct fpga_ip_info **infop)
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
};
#define to_bits_attr(_dev_attr)	\
	container_of(_dev_attr, struct bits_attribute, dev_attr)

#define __BITS_ATTR__(_name, _mode, _show, _store,			\
		      _off, _bits, _flip, _where)			\
{									\
	.dev_attr = {							\
		.attr = {.name = __stringify(_name), .mode = _mode },	\
		.show   = _show,					\
		.store  = _store,					\
	},								\
	.off = _off,							\
	.bits = _bits,							\
	.flip = _flip,							\
	.where = _where,						\
}

#define __BITS_ATTR(_name, __name, _mode, _off, _bits, _flip, _where)	\
struct bits_attribute bits_attr_ ## _name =				\
	__BITS_ATTR__(__name, _mode, _name ## _show, _name ## _store, _off, _bits, _flip, _where)

#define BITS_ATTR(_name, _mode, _off, _bits, _flip, _where)	\
	__BITS_ATTR(_name, _name, _mode, _off, _bits, _flip, _where)

#define BITS_ATTR_RW(_name, _off, _bits, _flip, _where)	\
	BITS_ATTR(_name, S_IWUSR | S_IRUGO, _off, _bits, _flip, _where)
#define BITS_ATTR_RO(_name, _off, _bits, _flip, _where)	\
	BITS_ATTR(_name, S_IRUGO, _off, _bits, _flip, _where)
#define BITS_ATTR_WO(_name, _off, _bits, _flip, _where)	\
	BITS_ATTR(_name, S_IWUSR, _off, _bits, _flip, _where)

#define BIT_ATTR_RW(_name, _off, _flip, _where)	\
	BITS_ATTR_RW(_name, _off, 1, _flip, _where)
#define BIT_ATTR_RO(_name, _off, _flip, _where)	\
	BITS_ATTR_RO(_name, _off, 1, _flip, _where)
#define BIT_ATTR_WO(_name, _off, _flip, _where)	\
	BITS_ATTR_WO(_name, _off, 1, _flip, _where)

ssize_t bits_attr_byte_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count);
ssize_t bits_attr_byte_show(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t bits_attr_word_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count);
ssize_t bits_attr_word_show(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t bits_attr_dword_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count);
ssize_t bits_attr_dword_show(struct device *dev, struct device_attribute *attr, char *buf);

ssize_t bits_attr_qword_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count);
ssize_t bits_attr_qword_show(struct device *dev, struct device_attribute *attr, char *buf);

#define BITS_ATTR_D(_type, _name, _mode, _off, _bits, _flip, _where)	\
struct bits_attribute bits_attr_ ## _name =				\
	__BITS_ATTR__(_name, _mode,					\
		      bits_attr_ ## _type ## _show,			\
		      bits_attr_ ## _type ## _store,			\
		      _off, _bits, _flip, _where)
#define BITS_ATTR_RW_D(_type, _name, _off, _bits, _flip, _where)	\
	BITS_ATTR_D(_type, _name, S_IWUSR | S_IRUGO, _off, _bits, _flip, _where)
#define BITS_ATTR_RO_D(_type, _name, _off, _bits, _flip, _where)	\
	BITS_ATTR_D(_type, _name, S_IRUGO, _off, _bits, _flip, _where)
#define BITS_ATTR_WO_D(_type, _name, _off, _bits, _flip, _where)	\
	BITS_ATTR_D(_type, _name, S_IWUSR, _off, _bits, _flip, _where)

#define BIT_ATTR_RW_D(_name, _off, _flip, _where)	\
	BITS_ATTR_RW_D(_name, _off, 1, _flip, _where)
#define BIT_ATTR_RO_D(_name, _off, _flip, _where)	\
	BITS_ATTR_RO_D(_name, _off, 1, _flip, _where)
#define BIT_ATTR_WO_D(_name, _off, _flip, _where)	\
	BITS_ATTR_WO_D(_name, _off, 1, _flip, _where)

#endif /* __KERNEL */

#endif /* __LINUX_FPGA_H */
