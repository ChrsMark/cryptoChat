/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 * 
 * Christos Markou <chrs.markx86@gmail.com>
 * Nikolaos Papadis <nikpapadis@gmail.com>
 * 
 *
 */

#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;
spinlock_t chdevlock;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");

	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	int host_fd = -1;
	unsigned long flags;

	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];

	unsigned int num_out, num_in;

	debug("Entering");

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		printk(KERN_DEBUG "thn katsame");
		debug("Could not find crypto device with %u minor", iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	num_out = 0;
	num_in = 0;

	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &(crof->host_fd), sizeof(crof->host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;
	
	/**
	 * Wait for the host to process our data.
	 **/
	//Lock
	spin_lock_irqsave(&chdevlock, flags);

	err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, 
	                        &syscall_type_sg, GFP_ATOMIC);
	err = virtqueue_kick(crdev->vq);
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;

	//Unlock
	spin_unlock_irqrestore(&chdevlock, flags);

	/* If host failed to open() return -ENODEV. */
	if (crof->host_fd < 0) {
		return -ENODEV;
	}
	else {
		debug("opened file successfully");
	}

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	unsigned int len;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;
	
	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	
	unsigned int num_out, num_in;
	int host_fd, err;
	unsigned long flags;

	debug("Entering");

	/**
	 * Send data to the host.
	 **/
	num_out = 0;
	num_in = 0;
	host_fd = crof->host_fd;

	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &host_fd, sizeof(host_fd));
	sgs[num_out++] = &host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	//Lock
	spin_lock_irqsave(&chdevlock, flags);

	err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, 
	                        &syscall_type_sg, GFP_ATOMIC);
	err = virtqueue_kick(crdev->vq);
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;

	//Unlock
	spin_unlock_irqrestore(&chdevlock, flags);

	kfree(crof);

	debug("Leaving");
	return ret;
}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	int i, ret = 0, err, retSes, ret2;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg, host_fd_sg, 
		ioctl_cmd_sg, session_key_sg, session_op_sg, host_return_val_sg, crypt_op_sg, src_sg, iv_sg, dst_sg,
		ses_id_sg, *sgs[8];
	unsigned int num_out, num_in,
	             syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL,
	             ioctl_cmd, len;
	int host_return_val;
	unsigned char *session_key, *src, *iv, *dst = NULL, *tmp_dst;
	struct session_op *session_op_ptr, host_session;
	struct crypt_op crypt_op, *crypt_op_ptr;
	unsigned long flags;
	__u32 *ses_id;

	session_op_ptr = NULL;
	crypt_op_ptr =NULL;

	debug("Entering");

	num_out = 0;
	num_in = 0;

	ioctl_cmd = cmd;

	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, &syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, &(crof->host_fd), sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;
	sg_init_one(&ioctl_cmd_sg, &ioctl_cmd, sizeof(ioctl_cmd));
	sgs[num_out++] = &ioctl_cmd_sg;


	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION: %d", crof->host_fd);

		session_op_ptr = (struct session_op *)arg;

		ret2 = copy_from_user(&host_session, session_op_ptr, sizeof(struct session_op));
		if (ret2) {
			debug("copy_from_user");
			return 1;
		}

		session_key = kmalloc(host_session.keylen+1, GFP_KERNEL);

		ret2 = copy_from_user(session_key, session_op_ptr->key, session_op_ptr->keylen*sizeof(unsigned char));

		session_key[host_session.keylen]='\0';

		sg_init_one(&session_key_sg, session_key, host_session.keylen);
		sgs[num_out++] = &session_key_sg;
		sg_init_one(&session_op_sg, &host_session, sizeof(host_session));
		sgs[num_out + num_in++] = &session_op_sg;		

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION: %d", crof->host_fd);

		ses_id = kmalloc(sizeof(__u32), GFP_KERNEL);

		ret2 = copy_from_user(ses_id, (void *)arg, sizeof(__u32));
		if (ret2) {
			debug("copy_from_user");
			return 1;
		}

		sg_init_one(&ses_id_sg, ses_id, sizeof(__u32));
		sgs[num_out++] = &ses_id_sg;

		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT: %d", crof->host_fd);

		crypt_op_ptr = (struct crypt_op *)arg;
		
		ret2 = copy_from_user(&crypt_op, crypt_op_ptr, sizeof(struct crypt_op));
		if (ret2) {
			debug("copy_from_user");
			return 1;
		}

		src = kmalloc(crypt_op.len, GFP_KERNEL);
		ret2 = copy_from_user(src, crypt_op_ptr->src, crypt_op.len * sizeof(unsigned char));

		iv = kmalloc(16, GFP_KERNEL);
		ret2 = copy_from_user(iv, crypt_op_ptr->iv, 16 * sizeof(unsigned char));

		dst = kmalloc(crypt_op.len, GFP_KERNEL);

		sg_init_one(&crypt_op_sg, &crypt_op, sizeof(crypt_op));
		sgs[num_out++] = &crypt_op_sg;
		sg_init_one(&src_sg, src, crypt_op.len * sizeof(unsigned char));
		sgs[num_out++] = &src_sg;
		sg_init_one(&iv_sg, iv, crypt_op.len * sizeof(unsigned char));
		sgs[num_out++] = &iv_sg;
		sg_init_one(&dst_sg, dst, crypt_op.len * sizeof(unsigned char));
		sgs[num_out + num_in++] = &dst_sg;

		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}
	
	sg_init_one(&host_return_val_sg, &host_return_val, sizeof(host_return_val));
	sgs[num_out + num_in++] = &host_return_val_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	/* Lock:
		Caller must ensure we don't call this with other virtqueue operations
		at the same time (except where noted).
		http://lxr.free-electrons.com/source/drivers/virtio/virtio_ring.c#L258
	 */
	//Lock
	spin_lock_irqsave(&chdevlock, flags);

	err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, 
	                        &syscall_type_sg, GFP_ATOMIC);

	/* http://lxr.free-electrons.com/source/drivers/virtio/virtio_ring.c#L404 */
	err = virtqueue_kick(crdev->vq);

	/* http://lxr.free-electrons.com/source/drivers/virtio/virtio_ring.c#L454 */
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;

	debug("Returned from trip to host\n");
	
	if (cmd == CIOCGSESSION) {
		// Return the session identifier to user.
		retSes = host_session.ses;
		ret2 = copy_to_user(&session_op_ptr->ses, &retSes, sizeof(retSes));
	}

	if (cmd == CIOCCRYPT) {	
		// Return encrypted/decrypted data to user.	
		ret2 = copy_to_user(crypt_op_ptr->dst, dst, crypt_op.len);
	}

	//Unlock
	spin_unlock_irqrestore(&chdevlock, flags);

	ret = host_return_val;

	if (ret) {
		debug("ioctl failed");
		return 1L;
	}

	debug("Leaving");

	return 0L;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
