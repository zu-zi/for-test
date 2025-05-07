# Linux源码阅读——文件系统篇
       ------文雯_2023090908027
# 基础结构体
## super_block
### super_block:fs.h:1470
struct super_block {
**struct list_head	s_list;**		/* Keep this first */
	dev_t			s_dev;		/* search index; _not_ kdev_t */
	unsigned char		s_blocksize_bits;
	unsigned long		s_blocksize;
	loff_t			s_maxbytes;	/* Max file size */
	struct file_system_type	*s_type;
**const struct super_operations	*s_op**;
	const struct dquot_operations	*dq_op;
	const struct quotactl_ops	*s_qcop;
	const struct export_operations *s_export_op;
	unsigned long		s_flags;
	unsigned long		s_iflags;	/* internal SB_I_* flags */
	unsigned long		s_magic;
**struct dentry		*s_root;**
	struct rw_semaphore	s_umount;
	int			s_count;
	atomic_t		s_active;
#ifdef CONFIG_SECURITY
	void                    *s_security;
#endif
	const struct xattr_handler **s_xattr;
#ifdef CONFIG_FS_ENCRYPTION
	const struct fscrypt_operations	*s_cop;
	struct fscrypt_keyring	*s_master_keys; /* master crypto keys in use */
#endif
#ifdef CONFIG_FS_VERITY
	const struct fsverity_operations *s_vop;
#endif
#if IS_ENABLED(CONFIG_UNICODE)
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
#endif
	struct hlist_bl_head	s_roots;	/* alternate root dentries for NFS */
	struct list_head	s_mounts;	/* list of mounts; _not_ for fs use */
**struct block_device	*s_bdev;**
	struct backing_dev_info *s_bdi;
	struct mtd_info		*s_mtd;
	struct hlist_node	s_instances;
	unsigned int		s_quota_types;	/* Bitmask of supported quota types */
	struct quota_info	s_dquot;	/* Diskquota specific options */

	struct sb_writers	s_writers;

	/*
	 * Keep s_fs_info, s_time_gran, s_fsnotify_mask, and
	 * s_fsnotify_marks together for cache efficiency. They are frequently
	 * accessed and rarely modified.
	 */
	void			*s_fs_info;	/* Filesystem private info */

	/* Granularity of c/m/atime in ns (cannot be worse than a second) */
	u32			s_time_gran;
	/* Time limits for c/m/atime in seconds */
	time64_t		   s_time_min;
	time64_t		   s_time_max;
#ifdef CONFIG_FSNOTIFY
	__u32			s_fsnotify_mask;
	struct fsnotify_mark_connector __rcu	*s_fsnotify_marks;
#endif

	char			s_id[32];	/* Informational name */
	uuid_t			s_uuid;		/* UUID */

	unsigned int		s_max_links;
	fmode_t			s_mode;

	/*
	 * The next field is for VFS *only*. No filesystems have any business
	 * even looking at it. You had been warned.
	 */
	struct mutex s_vfs_rename_mutex;	/* Kludge */

	/*
	 * Filesystem subtype.  If non-empty the filesystem type field
	 * in /proc/mounts will be "type.subtype"
	 */
	const char *s_subtype;

	const struct dentry_operations *s_d_op; /* default d_op for dentries */

	struct shrinker s_shrink;	/* per-sb shrinker handle */

	/* Number of inodes with nlink == 0 but still referenced */
	atomic_long_t s_remove_count;

	/*
	 * Number of inode/mount/sb objects that are being watched, note that
	 * inodes objects are currently double-accounted.
	 */
	atomic_long_t s_fsnotify_connectors;

	/* Being remounted read-only */
	int s_readonly_remount;

	/* per-sb errseq_t for reporting writeback errors via syncfs */
	errseq_t s_wb_err;

	/* AIO completions deferred from interrupt context */
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;

	/*
	 * Owning user namespace and default context in which to
	 * interpret filesystem uids, gids, quotas, device nodes,
	 * xattrs and security labels.
	 */
	struct user_namespace *s_user_ns;

	/*
	 * The list_lru structure is essentially just a pointer to a table
	 * of per-node lru lists, each of which has its own spinlock.
	 * There is no need to put them into separate cachelines.
	 */
	struct list_lru		s_dentry_lru;
	struct list_lru		s_inode_lru;
	struct rcu_head		rcu;
	struct work_struct	destroy_work;

	struct mutex		s_sync_lock;	/* sync serialisation lock */

	/*
	 * Indicates how deep in a filesystem stack this SB is
	 */
	int s_stack_depth;

	/* s_inode_list_lock protects s_inodes */
	spinlock_t		s_inode_list_lock ____cacheline_aligned_in_smp;
**struct list_head	s_inodes;**	/* all inodes */

	spinlock_t		s_inode_wblist_lock;
	struct list_head	s_inodes_wb;	/* writeback inodes */
} __randomize_layout;
### super_block解析
#### 挂载与标识相关
+ s_dev：挂载设备的编号（如 /dev/sda1）
+ s_id[32]：文件系统的名字，如 "ext4"，用于 /proc/mounts
+ s_uuid：UUID，唯一标识此文件系统
+ s_type：指向 file_system_type，表明是哪种文件系统类型（ext4、tmpfs等）
+ s_root：文件系统根目录对应的 dentry
#### 操作函数集（面向VFS的函数指针）
**这些函数是文件系统挂载时注册给 VFS 的接口，VFS 调用这些函数去操作具体的文件系统。**
+ s_op：super_operations*：super_block级操作，如alloc_inode、write_inode
+ dq_op：dquot_operations*：磁盘配额相关
+ s_qcop：quotactl_ops*：配额控制
+ s_export_op：export_operations*：网络导出相关（如NFS）
+ s_d_op：dentry_operations*：生成 dentry 时的默认操作集
#### 缓存与性能优化
+ s_dentry_lru、s_inode_lru：LRU缓存，用于回收闲置的目录项/inode
+ s_shrink：内存回收器（shrinker）注册点
+ s_fs_info：文件系统私有信息（如 ext4 superblock 的指针）
+ s_time_gran：时间精度，比如 ext4 是纳秒级
+ s_time_min/max：支持的时间戳最小/最大值
+ s_wb_err：用于 syncfs() 报告写回错误
#### 读写与并发控制
+ s_blocksize：块大小，单位字节
+ s_maxbytes：文件大小最大限制
+ s_umount：卸载锁
+ s_sync_lock：用于文件系统 sync 时加锁
+ s_inode_list_lock：用于保护 inode 链表的锁
#### inode与文件列表管理
+ s_inodes：所有 inode 组成的链表，
+ s_inodes_wb：正在进行 writeback 的 inode 列表
#### 挂载点与层次结构
+ s_mounts：所有的挂载点（mount）
+ s_stack_depth：文件系统嵌套深度（比如 aufs/bind mount）
+ s_instances：所有使用同一文件系统类型（如 ext4）的实例
#### 其它扩展字段（安全、加密、AIO等）
+ s_security：SELinux/AppArmor 用的安全上下文
+ s_cop、s_vop：文件加密 (fscrypt) 和完整性 (fsverity)
+ s_dio_done_wq：用于异步 IO 回调的工作队列
+ s_user_ns：用户命名空间信息，用于隔离多用户环境
### 小结
+ **VFS 会通过它找到当前挂载点的类型与根目录；**

+ **文件系统提供的核心操作会挂在这个结构体的函数指针上；**

+ **它管理着缓存、inode、挂载关系、权限、安全、配额、锁等几乎所有信息。**
## inode
### inode:fs.h:593
struct inode {
	umode_t i_mode;
	unsigned short i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;

#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
#endif

	const struct inode_operations *i_op;
**struct super_block *i_sb;**
	struct address_space *i_mapping;

#ifdef CONFIG_SECURITY
	void *i_security;
#endif

	/* Stat data, not accessed from path walking */
	unsigned long i_ino;
	/*
	 * Filesystems may only read i_nlink directly.  They shall use the
	 * following functions for modification:
	 *
	 *    (set|clear|inc|drop)_nlink
	 *    inode_(inc|dec)_link_count
	 */
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock; /* i_blocks, i_bytes, maybe i_size */
	unsigned short i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;

#ifdef __NEED_I_SIZE_ORDERED
	seqcount_t i_size_seqcount;
#endif

	/* Misc */
	unsigned long i_state;
	struct rw_semaphore i_rwsem;

	unsigned long dirtied_when; /* jiffies of first dirtying */
	unsigned long dirtied_time_when;

	struct hlist_node i_hash;
	struct list_head i_io_list; /* backing dev IO list */
#ifdef CONFIG_CGROUP_WRITEBACK
	struct bdi_writeback *i_wb; /* the associated cgroup wb */

	/* foreign inode detection, see wbc_detach_inode() */
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
#endif
	struct list_head i_lru; /* inode LRU list */
	struct list_head i_sb_list;
	struct list_head i_wb_list; /* backing dev writeback list */
	union {
		struct hlist_head i_dentry;
		struct rcu_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence; /* see futex */
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
#if defined(CONFIG_IMA) || defined(CONFIG_FILE_LOCKING)
	atomic_t i_readcount; /* struct files open RO */
#endif
	union {
		const struct file_operations
			*i_fop; /* former ->i_op->default_file_ops */
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned i_dir_seq;
	};

	__u32 i_generation;

#ifdef CONFIG_FSNOTIFY
	__u32 i_fsnotify_mask; /* all events this inode cares about */
	struct fsnotify_mark_connector __rcu *i_fsnotify_marks;
#endif

#ifdef CONFIG_FS_ENCRYPTION
	struct fscrypt_info *i_crypt_info;
#endif

#ifdef CONFIG_FS_VERITY
	struct fsverity_info *i_verity_info;
#endif

	void *i_private; /* fs or device private pointer */
} __randomize_layout;

### inode源码解析
**表示一个文件、目录、设备节点等的元数据。在内核中，它与 struct super_block 一起构成了文件系统的基础。**

struct inode 是 VFS（虚拟文件系统）层的抽象，用来描述一个文件或目录的“索引节点”。它不包含文件名，但包含文件权限、所属者、大小、时间戳、指向数据块的指针等信息。
####  权限与所有权管理
+ umode_t i_mode：文件类型和访问权限（如普通文件、目录、符号链接、rwx 权限等）。
+ kuid_t i_uid / kgid_t i_gid：文件的属主和属组。
+ unsigned int i_flags：如是否支持同步写入、是否为不可删除等。
#### 文件系统关联
+ const struct inode_operations *i_op：操作这个 inode 的函数指针表，如 create、lookup、mkdir 等。
+ struct super_block *i_sb：指向其所属的超级块，即哪个文件系统。
+ struct address_space *i_mapping：对应的页缓存映射，和内存页管理相关。
#### 文件信息
+ unsigned long i_ino：inode 编号，文件在文件系统内的唯一标识。
+ union { const unsigned int i_nlink; unsigned int __i_nlink; }：链接计数，即硬链接数目。
+ dev_t i_rdev：设备号（仅用于字符设备或块设备文件）。
+ loff_t i_size：文件大小。
+ struct timespec64 i_atime / i_mtime / i_ctime：访问、修改、创建时间。
#### 同步与并发控制
+ spinlock_t i_lock：保护 i_blocks, i_bytes 等字段的自旋锁。
+ struct rw_semaphore i_rwsem：用于文件级读写锁。
+ atomic_t i_count：引用计数。
+ atomic_t i_writecount：写引用计数。
#### 数据管理
+ struct address_space i_data：实际文件数据的页缓存（数据块管理）。
+ struct list_head i_devices：与设备文件相关联。
+ union：支持不同类型文件的具体数据指针（管道、字符设备、符号链接等）。
#### 文件操作与状态
+ const struct file_operations *i_fop：打开 inode 时使用的操作集合。
+ unsigned long i_state：inode 状态，如脏、锁定等。
+ atomic64_t i_version：文件内容版本号。
#### 其他：可选功能支持（通过内核配置项）
ACL & 安全、写回 & CGroup、文件系统通知、加密/校验
### 小结
+ 多态结构设计：通过 union 和操作函数指针支持不同文件类型（设备、目录、管道等）。
+ 性能优化：热字段靠前（如 i_mode, i_uid, i_size），频繁访问字段使用 atomic 类型。
+ 安全与灵活并重：支持 POSIX ACL、SELinux 安全模型、fscrypt 加密等现代安全机制。
+ 高度可扩展：通过内核配置开启/关闭字段，保持内核精简。
## dentry
### dentry:dcache.h:82
struct dentry {
	/* RCU lookup touched fields */
	unsigned int d_flags;		/* protected by d_lock */
	seqcount_spinlock_t d_seq;	/* per dentry seqlock */
	struct hlist_bl_node d_hash;	/* lookup hash list */
	struct dentry *d_parent;	/* parent directory */
	struct qstr d_name;
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */

	/* Ref lookup also touches following */
	struct lockref d_lockref;	/* per-dentry lock and refcount */
	const struct dentry_operations *d_op;
	struct super_block *d_sb;	/* The root of the dentry tree */
	unsigned long d_time;		/* used by d_revalidate */
	void *d_fsdata;			/* fs-specific data */

	union {
		struct list_head d_lru;		/* LRU list */
		wait_queue_head_t *d_wait;	/* in-lookup ones only */
	};
	struct list_head d_child;	/* child of parent list */
	struct list_head d_subdirs;	/* our children */
	/*
	 * d_alias and d_rcu can share memory
	 */
	union {
		struct hlist_node d_alias;	/* inode alias list */
		struct hlist_bl_node d_in_lookup_hash;	/* only for in-lookup ones */
	 	struct rcu_head d_rcu;
	} d_u;
} __randomize_layout;
### dentry源码解析
**struct dentry 是 Linux 虚拟文件系统（VFS）中的“目录项结构”。它的主要职责是在文件名（路径）与 inode（文件内容）之间建立映射，缓存路径解析结果，加速查找。**
#### 路径查找相关（路径缓存）
+ unsigned int d_flags：表示该目录项的状态（如是否在使用、是否负项等），受 d_lock 保护。
+ seqcount_spinlock_t d_seq：用于 seqlock 机制，保证目录项在多核下并发读写时的正确性。
+ struct hlist_bl_node d_hash：用于将 dentry 加入到 hash 表中，加速文件名查找。
#### 树结构与路径关系
+ struct dentry *d_parent：指向父目录的 dentry，构成目录树。
+ struct qstr d_name：该目录项在父目录中的名字，类型为 struct qstr，包含指针和长度。
+ unsigned char d_iname[DNAME_INLINE_LEN]：内联存储较短名字，避免频繁堆内存分配。
#### 文件映射（指向 inode）
+ struct inode *d_inode：指向该目录项所对应的文件（或目录）的 inode。如果为 NULL，说明是负项（negative dentry），表示此路径不存在。
#### 引用计数与锁机制
+ struct lockref d_lockref：结合自旋锁和引用计数的结构，用于并发控制该 dentry 的生命周期。
#### 文件系统与操作支持
+ const struct dentry_operations *d_op：dentry 层面的操作函数指针表，比如名称比较、缓存失效检查等。
+ struct super_block *d_sb：该目录项所在的超级块指针，即所在文件系统的根。
#### 辅助数据字段
+ unsigned long d_time：缓存时间戳，d_revalidate 操作时使用。
+ void *d_fsdata：由具体文件系统使用的私有数据指针。
#### 子目录管理
+ struct list_head d_child：挂载在父目录的子目录链表上。
+ struct list_head d_subdirs：所有直接子项组成的链表。
#### LRU缓存/等待队列
+ struct list_head d_lru：将未使用的 dentry 加入到 LRU 缓存链表。
+ wait_queue_head_t *d_wait：在查找尚未完成时加入等待队列。
#### inode 关联/RCU
```c
union {
	struct hlist_node d_alias;
	struct hlist_bl_node d_in_lookup_hash;
	struct rcu_head d_rcu;
};
```
+ d_alias：将多个指向同一个 inode 的 dentry 串成链表。
+ d_in_lookup_hash：用于路径查找中暂存未完成的项。
+ d_rcu：用于延迟销毁（RCU）机制，提升并发性能。
### 小结
#### 高效的路径查找：
+ 通过 d_hash 实现的 hash 表机制加速路径名查找。
+ d_seq + d_lockref 提供并发安全。
#### 灵活的层级组织
+ d_parent、d_child、d_subdirs 组成目录树，支持文件系统递归遍历。
#### 负项缓存机制
+ d_inode == NULL 表示目录项在文件系统中并不存在，有助于缓存失败结果，减少访问代价。
#### 内存优化
+ 使用内联字符串缓存 d_iname 和 d_lru 实现延迟释放与 LRU 管理。
+ 支持 RCU 回收机制，提升多核环境下的吞吐。
## file
### file:fs.h:940
struct file {
	union {
		struct llist_node f_llist;
		struct rcu_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	struct path f_path;
	struct inode *f_inode; /* cached value */
	const struct file_operations *f_op;

	/*
	 * Protects f_ep, f_flags.
	 * Must not be taken from IRQ context.
	 */
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;

	u64 f_version;
#ifdef CONFIG_SECURITY
	void *f_security;
#endif
	/* needed for tty driver, and maybe others */
	void *private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	struct hlist_head *f_ep;
#endif /* #ifdef CONFIG_EPOLL */
	struct address_space *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err; /* for syncfs */
} __randomize_layout __attribute__((
	aligned(4))); /* lest something weird decides that 2 is OK */

### file源码解析
struct file 是 Linux 内核中每一次打开文件操作的状态描述对象。

与 inode 表示“文件内容”、dentry 表示“路径”不同，file 表示“某个进程对某个文件的一次具体打开动作” 。
#### 文件路径与 inode 缓存
+ struct path f_path：是 struct path 类型，包含 dentry 和挂载点（mnt）。
+ struct inode *f_inode：指向当前文件的 inode，为 f_path.dentry->d_inode 的缓存，加快访问。
#### 文件操作函数集
+ const struct file_operations *f_op：文件操作函数指针表，定义 read、write、mmap 等函数指针。文件系统或驱动在文件打开时初始化这个指针。
#### 同步与访问控制
+ spinlock_t f_lock：保护 f_ep 与 f_flags，不能在中断上下文使用。
+ atomic_long_t f_count：引用计数，决定该结构何时释放。
+ unsigned int f_flags：open() 调用时传入的标志，如 O_RDONLY、O_NONBLOCK。
+ fmode_t f_mode：读/写权限掩码，常见值有 FMODE_READ、FMODE_WRITE。
#### 文件读写位置管理
+ loff_t f_pos：表示文件当前读写位置（偏移）。
+ struct mutex f_pos_lock：表于保护 f_pos，防止多线程读写位置冲突。
#### 所属进程与权限信息
+ struct fown_struct f_owner：记录拥有者，支持异步通知（如 F_SETOWN）。
+ const struct cred *f_cred：打开该文件时的权限信息（UID、GID 等），用于安全检查。
#### 文件读写辅助
+ struct file_ra_state f_ra：管理文件的预读机制（readahead），加速顺序访问。
#### 版本号与安全字段
+ u64 f_version：件偏移的版本号，用于缓存一致性。
+ void *f_security：安全模块（如 SELinux）使用的私有字段，仅在开启 CONFIG_SECURITY 时有效。
#### 驱动私有字段与 epoll
+ void *private_data：驱动或文件系统保存上下文用的数据指针。
+ struct hlist_head *f_ep：用于 epoll 事件机制的挂接钩子。
#### 写回/同步状态
+ struct address_space *f_mapping：页缓存地址空间对象，用于页缓存读写。
+ errseq_t f_wb_err：文件级别的写错误序号，用于 fsync() 检测错误。
+ errseq_t f_sb_err：超级块级别的写错误（用于 syncfs()）。

### 小结
RCU 与 lock-free：支持 RCU 回收机制，避免阻塞。

引用计数与延迟释放：自动管理生命周期，防止悬挂引用。

支持多种异步机制：如 epoll、异步 I/O、信号通知。

线程安全访问文件偏移：使用 f_pos_lock 保护。

# 文件打开流程
## open 整体调用流程
### 1：do_sys_open
long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
	struct open_how how = build_open_how(flags, mode);
	return do_sys_openat2(dfd, filename, &how);
} 
### 2：do_sys_openat2
static long do_sys_openat2(int dfd, const char __user *filename,
			   struct open_how *how)
{
	struct open_flags op;
	int fd = build_open_flags(how, &op);
	struct filename *tmp;

	if (fd)
		return fd;

	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(how->flags);
	if (fd >= 0) {
		struct file *f = do_filp_open(dfd, tmp, &op);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fsnotify_open(f);
			fd_install(fd, f);
		}
	}
	putname(tmp);
	return fd;
}
+ do_sys_openat2() 是 open() 系统调用在内核空间中的主入口之一，它完成如下几项关键工作：
   + 1：解析并校验 open 参数：build_open_flags()
   + 2：拷贝用户态路径名：getname()
   + 3：分配文件描述符：get_unused_fd_flags()
   + 4：调用内核打开文件主逻辑：do_filp_open()
   + 5：安装文件描述符：fd_install()
   + 6：清理：putname()、错误处理
### 3：do_filp_open
struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	set_nameidata(&nd, dfd, pathname, NULL);
	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	return filp;
}
+ 该函数是 VFS 中“打开文件”的关键函数之一。它负责初始化路径解析所需的数据结构 nameidata，并调用 path_openat() 进行路径查找与文件打开。
1. set_nameidata(&nd, dfd, pathname, NULL);
设置当前线程的 nameidata 上下文（用于路径名解析）。

dfd 是目录文件描述符，pathname 是路径名，作用是支持相对路径。

2. filp = path_openat(&nd, op, flags | LOOKUP_RCU);
这是文件打开的核心函数调用，执行路径解析与打开操作。

LOOKUP_RCU 表示首次尝试以 RCU 模式查找路径（效率更高）。

3. if (unlikely(filp == ERR_PTR(-ECHILD)))
如果 RCU 模式失败（比如因路径复杂），会 fallback 到普通模式 LOOKUP_FOLLOW。

4. if (unlikely(filp == ERR_PTR(-ESTALE)))
如果缓存信息过时，会再次尝试路径解析，使用 LOOKUP_REVAL 强制重新验证。

5. restore_nameidata();
恢复原先的 nameidata 上下文，清理工作。
### 4：path_openat
static struct file *path_openat(struct nameidata *nd,
			const struct open_flags *op, unsigned flags)
{
	struct file *file;
	int error;

	file = alloc_empty_file(op->open_flag, current_cred());
	if (IS_ERR(file))
		return file;

	if (unlikely(file->f_flags & __O_TMPFILE)) {
		error = do_tmpfile(nd, flags, op, file);
	} else if (unlikely(file->f_flags & O_PATH)) {
		error = do_o_path(nd, flags, file);
	} else {
		const char *s = path_init(nd, flags);
		while (!(error = link_path_walk(s, nd)) &&
		       (s = open_last_lookups(nd, file, op)) != NULL)
			;
		if (!error)
			error = do_open(nd, file, op);
		terminate_walk(nd);
	}
	if (likely(!error)) {
		if (likely(file->f_mode & FMODE_OPENED))
			return file;
		WARN_ON(1);
		error = -EINVAL;
	}
	fput(file);
	if (error == -EOPENSTALE) {
		if (flags & LOOKUP_RCU)
			error = -ECHILD;
		else
			error = -ESTALE;
	}
	return ERR_PTR(error);
}
+ path_openat() 是 VFS 打开文件流程中的核心调度函数.

分配空的 struct file 对象；

执行路径解析；

最终调用 do_open() 来完成文件打开（包括查 inode、创建文件等）。

1. file = alloc_empty_file(op->open_flag, current_cred());
分配一个空的 struct file 结构体并初始化；

如果失败，直接返回错误指针。

2. 特殊路径处理：
```c
if (unlikely(file->f_flags & __O_TMPFILE)) {
    error = do_tmpfile(nd, flags, op, file);
} else if (unlikely(file->f_flags & O_PATH)) {
    error = do_o_path(nd, flags, file);
}
```
如果是 O_TMPFILE 或 O_PATH 打开模式，调用特殊处理函数：

do_tmpfile()：用于 O_TMPFILE 匿名文件创建；

do_o_path()：用于 O_PATH，不打开文件内容，仅获取路径信息。

→ 若不是上述模式，就进入标准打开流程。

3. 标准路径打开流程：
```c
const char *s = path_init(nd, flags);
while (!(error = link_path_walk(s, nd)) &&
       (s = open_last_lookups(nd, file, op)) != NULL)
    ;
if (!error)
    error = do_open(nd, file, op);
terminate_walk(nd);
```
path_init()：初始化路径解析（如判断是绝对路径还是相对路径），返回起始路径名 s；

link_path_walk()：逐层遍历路径（如 /a/b/c），直到最后一层；

open_last_lookups()：处理最后一个路径分量（例如 c），决定是查找还是创建；

do_open()：实际打开文件（读取 inode、权限检查、创建新文件等）；

terminate_walk()：清理路径解析过程。

4. 错误处理和资源释放：
```c
if (likely(!error)) {
    if (likely(file->f_mode & FMODE_OPENED))
        return file;
    WARN_ON(1);
    error = -EINVAL;
}
```
如果打开成功并设置了 FMODE_OPENED，说明文件被成功打开，返回 file；

否则警告，并释放资源 fput(file)。
### 5：do_open
static int do_open(struct nameidata *nd,
		   struct file *file, const struct open_flags *op)
{
	struct user_namespace *mnt_userns;
	int open_flag = op->open_flag;
	bool do_truncate;
	int acc_mode;
	int error;

	if (!(file->f_mode & (FMODE_OPENED | FMODE_CREATED))) {
		error = complete_walk(nd);
		if (error)
			return error;
	}
	if (!(file->f_mode & FMODE_CREATED))
		audit_inode(nd->name, nd->path.dentry, 0);
	mnt_userns = mnt_user_ns(nd->path.mnt);
	if (open_flag & O_CREAT) {
		if ((open_flag & O_EXCL) && !(file->f_mode & FMODE_CREATED))
			return -EEXIST;
		if (d_is_dir(nd->path.dentry))
			return -EISDIR;
		error = may_create_in_sticky(mnt_userns, nd,
					     d_backing_inode(nd->path.dentry));
		if (unlikely(error))
			return error;
	}
	if ((nd->flags & LOOKUP_DIRECTORY) && !d_can_lookup(nd->path.dentry))
		return -ENOTDIR;

	do_truncate = false;
	acc_mode = op->acc_mode;
	if (file->f_mode & FMODE_CREATED) {
		/* Don't check for write permission, don't truncate */
		open_flag &= ~O_TRUNC;
		acc_mode = 0;
	} else if (d_is_reg(nd->path.dentry) && open_flag & O_TRUNC) {
		error = mnt_want_write(nd->path.mnt);
		if (error)
			return error;
		do_truncate = true;
	}
	error = may_open(mnt_userns, &nd->path, acc_mode, open_flag);
	if (!error && !(file->f_mode & FMODE_OPENED))
		error = vfs_open(&nd->path, file);
	if (!error)
		error = ima_file_check(file, op->acc_mode);
	if (!error && do_truncate)
		error = handle_truncate(mnt_userns, file);
	if (unlikely(error > 0)) {
		WARN_ON(1);
		error = -EINVAL;
	}
	if (do_truncate)
		mnt_drop_write(nd->path.mnt);
	return error;
}
do_open() 是整个文件打开路径中完成“打开”行为的关键步骤：

它在前面的路径解析、权限检查完成后，真正对 inode 进行 vfs_open() 操作；

对应用户传入的标志位（如 O_CREAT、O_TRUNC）执行权限验证、可能创建文件、可能截断文件；

最终关联 file 对象与打开的文件。

1. 文件状态检查与路径准备：
```c
if (!(file->f_mode & (FMODE_OPENED | FMODE_CREATED))) {
	error = complete_walk(nd);
	if (error)
		return error;
}
```
如果文件还没标记为已打开或已创建，则执行 complete_walk(nd)：

这是路径解析完成后的“最后一步”，确保路径信息完整并锁定 dentry。

2. 审计信息与创建标志处理：
```c
if (!(file->f_mode & FMODE_CREATED))
	audit_inode(nd->name, nd->path.dentry, 0);
```
对未创建新文件的情况，记录审计信息（可忽略分析）。

3. 处理 O_CREAT/O_EXCL 模式：
```c
if (open_flag & O_CREAT) {
	if ((open_flag & O_EXCL) && !(file->f_mode & FMODE_CREATED))
		return -EEXIST;
	if (d_is_dir(nd->path.dentry))
		return -EISDIR;
	error = may_create_in_sticky(mnt_userns, nd, d_backing_inode(nd->path.dentry));
	if (unlikely(error))
		return error;
}
```
若是 O_CREAT | O_EXCL 且文件已存在 → 返回 -EEXIST；

若目标是目录 → 报错；

may_create_in_sticky() 检查粘滞位 sticky bit 权限。

4. 检查是否要求是目录：
```c
if ((nd->flags & LOOKUP_DIRECTORY) && !d_can_lookup(nd->path.dentry))
	return -ENOTDIR;
```
5. 权限模式和截断标志分析：
```c
do_truncate = false;
acc_mode = op->acc_mode;
if (file->f_mode & FMODE_CREATED) {
	open_flag &= ~O_TRUNC;
	acc_mode = 0;
} else if (d_is_reg(nd->path.dentry) && open_flag & O_TRUNC) {
	error = mnt_want_write(nd->path.mnt);
	if (error)
		return error;
	do_truncate = true;
}
```
如果新创建文件，则无需截断；

如果是已有普通文件 + O_TRUNC，则先申请写权限（因为会修改 inode）。

6. 权限验证：
```c
error = may_open(mnt_userns, &nd->path, acc_mode, open_flag);
```
调用 may_open() 验证权限（读写执行等）是否合法。

7. 核心跳转：调用 vfs_open() 打开文件
```c
if (!error && !(file->f_mode & FMODE_OPENED))
	error = vfs_open(&nd->path, file);
```
8. 安全模块检查 + 截断处理：
```c
if (!error)
	error = ima_file_check(file, op->acc_mode); // 完整性模块（如SELinux）
if (!error && do_truncate)
	error = handle_truncate(mnt_userns, file);  // 执行truncate操作
```
9. 错误转换、权限释放：
```c
if (unlikely(error > 0)) {
	WARN_ON(1);
	error = -EINVAL;
}
if (do_truncate)
	mnt_drop_write(nd->path.mnt);
return error;
```
### 6：vfs_open
int vfs_open(const struct path *path, struct file *file)
{
	file->f_path = *path;
	return do_dentry_open(file, d_backing_inode(path->dentry), NULL);
}
+ 这是文件打开的核心入口，正式将文件和 inode 联系起来，为后续访问（read/write/mmap）做好准备。

主要工作是：

1、设置 file->f_path；

2、调用 do_dentry_open()

### 7：do_dentry_open
static int do_dentry_open(struct file *f,
			  struct inode *inode,
			  int (*open)(struct inode *, struct file *))
{
	static const struct file_operations empty_fops = {};
	int error;

	path_get(&f->f_path);
	f->f_inode = inode;
	f->f_mapping = inode->i_mapping;
	f->f_wb_err = filemap_sample_wb_err(f->f_mapping);
	f->f_sb_err = file_sample_sb_err(f);

	if (unlikely(f->f_flags & O_PATH)) {
		f->f_mode = FMODE_PATH | FMODE_OPENED;
		f->f_op = &empty_fops;
		return 0;
	}

	if ((f->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ) {
		i_readcount_inc(inode);
	} else if (f->f_mode & FMODE_WRITE && !special_file(inode->i_mode)) {
		error = get_write_access(inode);
		if (unlikely(error))
			goto cleanup_file;
		error = __mnt_want_write(f->f_path.mnt);
		if (unlikely(error)) {
			put_write_access(inode);
			goto cleanup_file;
		}
		f->f_mode |= FMODE_WRITER;
	}

	/* POSIX.1-2008/SUSv4 Section XSI 2.9.7 */
	if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))
		f->f_mode |= FMODE_ATOMIC_POS;

	f->f_op = fops_get(inode->i_fop);
	if (WARN_ON(!f->f_op)) {
		error = -ENODEV;
		goto cleanup_all;
	}

	error = security_file_open(f);
	if (error)
		goto cleanup_all;

	error = break_lease(locks_inode(f), f->f_flags);
	if (error)
		goto cleanup_all;

	/* normally all 3 are set; ->open() can clear them if needed */
	f->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
	if (!open)
		open = f->f_op->open;
	if (open) {
		error = open(inode, f);
		if (error)
			goto cleanup_all;
	}
	f->f_mode |= FMODE_OPENED;
	if ((f->f_mode & FMODE_READ) &&
	     likely(f->f_op->read || f->f_op->read_iter))
		f->f_mode |= FMODE_CAN_READ;
	if ((f->f_mode & FMODE_WRITE) &&
	     likely(f->f_op->write || f->f_op->write_iter))
		f->f_mode |= FMODE_CAN_WRITE;
	if ((f->f_mode & FMODE_LSEEK) && !f->f_op->llseek)
		f->f_mode &= ~FMODE_LSEEK;
	if (f->f_mapping->a_ops && f->f_mapping->a_ops->direct_IO)
		f->f_mode |= FMODE_CAN_ODIRECT;

	f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	f->f_iocb_flags = iocb_flags(f);

	file_ra_state_init(&f->f_ra, f->f_mapping->host->i_mapping);

	if ((f->f_flags & O_DIRECT) && !(f->f_mode & FMODE_CAN_ODIRECT))
		return -EINVAL;

	/*
	 * XXX: Huge page cache doesn't support writing yet. Drop all page
	 * cache for this file before processing writes.
	 */
	if (f->f_mode & FMODE_WRITE) {
		/*
		 * Paired with smp_mb() in collapse_file() to ensure nr_thps
		 * is up to date and the update to i_writecount by
		 * get_write_access() is visible. Ensures subsequent insertion
		 * of THPs into the page cache will fail.
		 */
		smp_mb();
		if (filemap_nr_thps(inode->i_mapping)) {
			struct address_space *mapping = inode->i_mapping;

			filemap_invalidate_lock(inode->i_mapping);
			/*
			 * unmap_mapping_range just need to be called once
			 * here, because the private pages is not need to be
			 * unmapped mapping (e.g. data segment of dynamic
			 * shared libraries here).
			 */
			unmap_mapping_range(mapping, 0, 0, 0);
			truncate_inode_pages(mapping, 0);
			filemap_invalidate_unlock(inode->i_mapping);
		}
	}

	return 0;

cleanup_all:
	if (WARN_ON_ONCE(error > 0))
		error = -EINVAL;
	fops_put(f->f_op);
	put_file_access(f);
cleanup_file:
	path_put(&f->f_path);
	f->f_path.mnt = NULL;
	f->f_path.dentry = NULL;
	f->f_inode = NULL;
	return error;
}
+ 该函数最终完成了一个文件 struct file 的初始化（比如：inode、f_op、权限标志位等），并调用底层文件系统的 ->open() 回调，正式完成“打开”一个文件的动作。

1. 设置路径和 inode 基础属性
```c
path_get(&f->f_path);
f->f_inode = inode;
f->f_mapping = inode->i_mapping;
```
把 inode 和路径信息设置进 file，file->f_mapping 是页缓存的入口。

2. 处理 O_PATH 特殊标志
```c
if (unlikely(f->f_flags & O_PATH)) {
	f->f_mode = FMODE_PATH | FMODE_OPENED;
	f->f_op = &empty_fops;
	return 0;
}
```
O_PATH 打开的是一个“路径句柄”，不是实际的文件读写，所以这里直接返回。

3. 处理读写权限
```c
if ((f->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ) {
	i_readcount_inc(inode);
} else if (f->f_mode & FMODE_WRITE && !special_file(inode->i_mode)) {
	error = get_write_access(inode);
	...
}
```
如果是写操作，还要获取对 inode 的写权限，以及挂载点的写权限 __mnt_want_write()。

4. 设置原子性标志（ATOMIC_POS）用于 pread/pwrite
```c
if (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode))
	f->f_mode |= FMODE_ATOMIC_POS;
```
5. **获取并设置 file_operations**
```c
f->f_op = fops_get(inode->i_fop);
if (WARN_ON(!f->f_op)) {
	error = -ENODEV;
	goto cleanup_all;
}
```
这是最终使用 vfs_read() 等调用时的行为绑定的地方！

6. 安全检查与租约破坏
```c
error = security_file_open(f);
...
error = break_lease(locks_inode(f), f->f_flags);
```
检查安全模块（如 SELinux）和破坏已有租约（lease）以避免冲突。

7. 调用底层 ->open() 实现
```c
if (!open)
	open = f->f_op->open;
if (open)
	error = open(inode, f);
```
这是真正进入 ext4、xfs 等底层文件系统的钩子调用。

8. 设置各种模式标志
```c
f->f_mode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
f->f_mode |= FMODE_CAN_READ / FMODE_CAN_WRITE
f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
```
这些 flag 会影响后续 read/write/seek 的行为。

9. 处理 Direct I/O 和 Huge Page 清理
```c
if ((f->f_flags & O_DIRECT) && !(f->f_mode & FMODE_CAN_ODIRECT))
	return -EINVAL;

if (f->f_mode & FMODE_WRITE) {
	// 清理页缓存中的 huge page，确保 Direct I/O 不出错
}
```
正常返回 0，错误则统一清理资源并返回 error。
+ 总结：do_dentry_open() 是 VFS 层打开文件的最终一步：
  + 绑定 inode 与 file；
	+ 安全检查、安全模块处理；
	+ 调用实际的文件系统 ->open()；
	+ 设置各种权限与 flag；
	+ 完成一个 file 结构体的“合法化”。

### 成功打开文件！
open()打开文件后：
+ 一个有效的文件描述符 fd；
+ 一个内核中的 struct file 对象；
+ 与该 file 对象关联的：
   + 路径 f->f_path
	 + inode f->f_inode
	 + 读写接口 f->f_op（来自 inode->i_fop）
	 + 缓存映射 f->f_mapping
从此之后，read/write/seek/mmap 等系统调用都将基于这个 struct file 对象工作。

## 一、系统调用入口：fs/open.c:1334
```c
long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
	struct open_how how = build_open_how(flags, mode);
	return do_sys_openat2(dfd, filename, &how);
}
```
## 二、路径查找阶段
从路径字符串 /home/test.txt 查到对应的 dentry。
### lookup_fast
static struct dentry *lookup_fast(struct nameidata *nd)
{
	struct dentry *dentry, *parent = nd->path.dentry;
	int status = 1;

	/*
	 * Rename seqlock is not required here because in the off chance
	 * of a false negative due to a concurrent rename, the caller is
	 * going to fall back to non-racy lookup.
	 */
	if (nd->flags & LOOKUP_RCU) {
		dentry = __d_lookup_rcu(parent, &nd->last, &nd->next_seq);
		if (unlikely(!dentry)) {
			if (!try_to_unlazy(nd))
				return ERR_PTR(-ECHILD);
			return NULL;
		}

		/*
		 * This sequence count validates that the parent had no
		 * changes while we did the lookup of the dentry above.
		 */
		if (read_seqcount_retry(&parent->d_seq, nd->seq))
			return ERR_PTR(-ECHILD);

		status = d_revalidate(dentry, nd->flags);
		if (likely(status > 0))
			return dentry;
		if (!try_to_unlazy_next(nd, dentry))
			return ERR_PTR(-ECHILD);
		if (status == -ECHILD)
			/* we'd been told to redo it in non-rcu mode */
			status = d_revalidate(dentry, nd->flags);
	} else {
		dentry = __d_lookup(parent, &nd->last);
		if (unlikely(!dentry))
			return NULL;
		status = d_revalidate(dentry, nd->flags);
	}
	if (unlikely(status <= 0)) {
		if (!status)
			d_invalidate(dentry);
		dput(dentry);
		return ERR_PTR(status);
	}
	return dentry;
}
这是 Linux 文件路径解析中的优化路径，在路径查找时，内核会优先尝试通过 dcache 快速找到目标目录项，以避免昂贵的磁盘访问。

它的作用是：

在已有路径 nd->path 的基础上，根据下一个路径分量 nd->last，快速查找对应的 dentry 目录项（如果失败再走慢路径 lookup_slow()）。

lookup_fast() 是 Linux 内核路径查找过程中优化性能的关键函数。它通过 dcache 实现对路径分量的快速解析，分为两种路径：

+ RCU路径：利用 RCU 技术在无锁的情况下尝试从 dentry 缓存中读取，提高并发性能。

+ 非RCU路径：传统查找方式，从父目录中找目标 dentry。

函数中会调用 d_revalidate() 判断 dentry 是否依旧有效，若无效则走慢路径。通过这种“快失败，慢备份”的方式实现路径解析性能和准确性的平衡。

### lookup_slow
static struct dentry *lookup_slow(const struct qstr *name,
				  struct dentry *dir,
				  unsigned int flags)
{
	struct inode *inode = dir->d_inode;
	struct dentry *res;
	inode_lock_shared(inode);
	res = __lookup_slow(name, dir, flags);
	inode_unlock_shared(inode);
	return res;
}
当 lookup_fast() 无法命中 dcache 或路径已过期时，lookup_slow() 会执行真实的底层查找，通常意味着需要与底层文件系统交互（比如 ext4、xfs 等），以获取或创建新的 dentry。

lookup_slow() 是路径查找过程中的慢路径，当 lookup_fast() 无法命中缓存时调用。它通过获取目标目录的 inode 共享锁，调用 __lookup_slow() 去执行底层文件系统的查找函数，从而获取最新的目录项 dentry。

它确保路径查找过程的准确性和一致性，是路径解析中从缓存退化到真实查找的关键一环。
## 三、inode获取阶段
struct inode *iget_locked(struct super_block *sb, unsigned long ino)
{
	struct hlist_head *head = inode_hashtable + hash(sb, ino);
	struct inode *inode;
again:
	spin_lock(&inode_hash_lock);
	inode = find_inode_fast(sb, head, ino);
	spin_unlock(&inode_hash_lock);
	if (inode) {
		if (IS_ERR(inode))
			return NULL;
		wait_on_inode(inode);
		if (unlikely(inode_unhashed(inode))) {
			iput(inode);
			goto again;
		}
		return inode;
	}

	inode = alloc_inode(sb);
	if (inode) {
		struct inode *old;

		spin_lock(&inode_hash_lock);
		/* We released the lock, so.. */
		old = find_inode_fast(sb, head, ino);
		if (!old) {
			inode->i_ino = ino;
			spin_lock(&inode->i_lock);
			inode->i_state = I_NEW;
			hlist_add_head_rcu(&inode->i_hash, head);
			spin_unlock(&inode->i_lock);
			inode_sb_list_add(inode);
			spin_unlock(&inode_hash_lock);

			/* Return the locked inode with I_NEW set, the
			 * caller is responsible for filling in the contents
			 */
			return inode;
		}

		/*
		 * Uhhuh, somebody else created the same inode under
		 * us. Use the old inode instead of the one we just
		 * allocated.
		 */
		spin_unlock(&inode_hash_lock);
		destroy_inode(inode);
		if (IS_ERR(old))
			return NULL;
		inode = old;
		wait_on_inode(inode);
		if (unlikely(inode_unhashed(inode))) {
			iput(inode);
			goto again;
		}
	}
	return inode;
}
EXPORT_SYMBOL(iget_locked);

代码理解：
+ 在系统的 inode 哈希表中查找是否已经存在对应的 inode。
+ 如果找不到，则分配一个新的 inode 并插入 inode 哈希表中（暂时标记为 I_NEW 状态，等待填充）。

第二阶段是 inode 获取阶段，通过 iget_locked() 实现，它是 VFS 中用于根据 inode 号获取（或构造） inode 对象的标准方式。

其完整流程如下：

在 inode 哈希表中查找已有的 inode（find_inode_fast()）；

若找到了： 　　
+ 等待 inode 被初始化完毕（wait_on_inode()）； 　　
+ 如果 inode 已被从哈希表移除（inode_unhashed()），则释放后重试；

若没找到： 　　
+ 调用 alloc_inode() 分配新 inode； 　　
- 加入哈希表，标记为 I_NEW 状态（表明还没被底层文件系统填充）； 　　
- 返回该“锁住”的 inode，等待文件系统继续初始化。

该函数确保：

+ 同一 inode 在系统中只存在一个实例；

+ inode 的初始化是线程安全的；

+ 支持“延迟初始化”，即分配后由具体文件系统（如 ext4）完成 inode 内容加载。

iget_locked() 是 VFS 打开文件过程中获取 inode 的关键函数。在路径查找到最终文件名后，VFS 需要通过设备号和 inode 号，定位或新建对应的 inode。它保障了 inode 的唯一性、正确性和延迟填充机制。

性能对比：
+ 缓存命中：约100纳秒级
+ 磁盘读取：毫秒级（机械磁盘更慢）
### 调用点
lookup_slow() → __lookup_slow() → dir->d_inode->i_op->lookup()
## 四、文件对象创建
do_dentry_open()前面已讲
+ f->f_inode = inode
+ f->f_op = inode->i_fop
+ open(inode, f)
+ 设置 f->f_mode、f->f_flags
+ 注册到 fd 表中
## 五、错误处理
常见错误路径：
+ ENOENT：lookup_slow()未找到目标文件。
+ EACCES：may_open()权限校验失败。
+ ELOOP：符号链接递归过深。