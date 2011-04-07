/*
 * MTP function driver
 *
 * Copyright (C) 2010 HTC Corporation
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
/*
#define DEBUG
#define VERBOSE_DEBUG
*/
#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/interrupt.h>

#include <linux/types.h>
#include <linux/device.h>
#include <linux/miscdevice.h>

#include <linux/usb/android_composite.h>

#define BULK_BUFFER_SIZE           16384

/* number of tx requests to allocate */
#define REQ_MAX 4

/* please refer: Documentation/ioctl-number.txt and Documentation/ioctl/
 * and choice magic-number */
#define USB_MTP_IOC_MAGIC 0xFF

#define MTP_IOC_GET_CANCEL_REQUEST_ID	_IOR(USB_MTP_IOC_MAGIC, 0x21, __u32)
#define MTP_IOC_SET_DEVICE_STATUS	_IOW(USB_MTP_IOC_MAGIC, 0x26, int)

/* base on Annex. D in PIMA15740-2000 spec */
#define PIMA15740_CANCEL_REQUEST 0x64
#define PIMA15740_GET_EXTENDED_EVENT_DATA 0x65
#define PIMA15740_DEVICE_RESET_REQUEST 0x66
#define PIMA15740_GET_DEVICE_STATUS 0x67

#define STATUS_OK	0x2001
#define STATUS_BUSY	0x2019

#define NUM_EVENT	5
#define MAX_EVENT_SIZE	30
struct cancel_request_data {
	__le16	wCode;
	__le32	dwTransactionID;
} __attribute__ ((packed));

struct get_dev_status_data {
	__le16	wLength;
	__le16	wCode;
} __attribute__ ((packed));

enum {
	EVENT_ONLINE = 0,
	EVENT_OFFLINE,
	EVENT_CANCEL_REQUEST,
	EVENT_DEVICE_RESET,
	EVENT_GET_DEVICE_STATUS,
};

static char *event_string[NUM_EVENT] = {
	"online",
	"offline",
	"Cancel_Request",
	"Device_Reset",
	"Get_Device_Status",
};

static const char shortname[] = "android_mtp";

struct mtp_dev {
	struct usb_function function;
	struct usb_composite_dev *cdev;
	spinlock_t lock;

	struct usb_ep *ep_in;
	struct usb_ep *ep_out;
	struct usb_ep *ep_notify;

	int online;
	int error;

	atomic_t read_excl;
	atomic_t write_excl;
	atomic_t open_excl;
	atomic_t event_open_excl;
	atomic_t event_excl;
	atomic_t ctl_open_excl;
	atomic_t ctl_read_excl;
	atomic_t ctl_ioctl_excl;

	struct list_head tx_idle;
	struct list_head rx_idle;
	struct list_head rx_done;

	wait_queue_head_t read_wq;
	wait_queue_head_t write_wq;
	wait_queue_head_t ctl_read_wq;
	wait_queue_head_t notify_wq;
	struct usb_request *notify_req;
	struct usb_request *read_req;
	int notify_in_process;
	u32 event;
	unsigned read_count;
	unsigned char *read_buf;
	struct cancel_request_data cr_data;
	u16 dev_status;
	u8 flush_rx_queue;
};

static struct usb_interface_descriptor mtp_interface_desc = {
	.bLength                = USB_DT_INTERFACE_SIZE,
	.bDescriptorType        = USB_DT_INTERFACE,
	.bInterfaceNumber       = 0,
	.bNumEndpoints          = 3,
	.bInterfaceClass        = 0xFF,
	.bInterfaceSubClass     = 0,
	.bInterfaceProtocol     = 0,
};

static struct usb_endpoint_descriptor mtp_hs_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor mtp_hs_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor mtp_hs_notify_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_INT,
	.wMaxPacketSize         = __constant_cpu_to_le16(64),
	.bInterval              = 9,
};

static struct usb_endpoint_descriptor mtp_fs_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(64),
};

static struct usb_endpoint_descriptor mtp_fs_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = __constant_cpu_to_le16(64),
};

static struct usb_endpoint_descriptor mtp_fs_notify_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_INT,
	.bInterval              = 32,
	.wMaxPacketSize         = __constant_cpu_to_le16(64),
};

static struct usb_descriptor_header *fs_mtp_descs[] = {
	(struct usb_descriptor_header *) &mtp_interface_desc,
	(struct usb_descriptor_header *) &mtp_fs_in_desc,
	(struct usb_descriptor_header *) &mtp_fs_out_desc,
	(struct usb_descriptor_header *) &mtp_fs_notify_desc,
	NULL,
};

static struct usb_descriptor_header *hs_mtp_descs[] = {
	(struct usb_descriptor_header *) &mtp_interface_desc,
	(struct usb_descriptor_header *) &mtp_hs_in_desc,
	(struct usb_descriptor_header *) &mtp_hs_out_desc,
	(struct usb_descriptor_header *) &mtp_hs_notify_desc,
	NULL,
};


#define MS_VENDOR_CODE	0x0b
/* "MSFT100" */
static char string_MS_OS_DESC[] = { 0x4d, 0x53, 0x46, 0x54, 0x31, 0x30,
			0x30, MS_VENDOR_CODE, 0};
/* OS string descriptor, in UTF-8 */
static struct usb_string os_string_defs[] = {
	[0].id = 0xee,
	[0].s = string_MS_OS_DESC,
	{  /* ZEROES END LIST */ },
};

static struct usb_gadget_strings os_string_table = {
	.language =		0,
	.strings =		os_string_defs,
};

static struct usb_string mtp_string_defs[] = {
	[0].s = "HTC MTP",
	{  /* ZEROES END LIST */ },
};

static struct usb_gadget_strings mtp_string_table = {
	.language =		0x0409,	/* en-us */
	.strings =		mtp_string_defs,
};
static struct usb_gadget_strings *mtp_strings[] = {
	&os_string_table,
	&mtp_string_table,
	NULL,
};

/* temporary variable used between mtp_open() and mtp_gadget_bind() */
static struct mtp_dev *_mtp_dev;

static inline struct mtp_dev *func_to_dev(struct usb_function *f)
{
	return container_of(f, struct mtp_dev, function);
}

static struct usb_request *mtp_request_new(struct usb_ep *ep, int buffer_size)
{
	struct usb_request *req = usb_ep_alloc_request(ep, GFP_KERNEL);
	if (!req)
		return NULL;

	/* now allocate buffers for the requests */
	req->buf = kmalloc(buffer_size, GFP_KERNEL);
	if (!req->buf) {
		usb_ep_free_request(ep, req);
		return NULL;
	}

	return req;
}

static void mtp_request_free(struct usb_request *req, struct usb_ep *ep)
{
	if (req) {
		kfree(req->buf);
		usb_ep_free_request(ep, req);
	}
}

static inline int _lock(atomic_t *excl)
{
	if (atomic_inc_return(excl) == 1) {
		return 0;
	} else {
		atomic_dec(excl);
		return -1;
	}
}

static inline void _unlock(atomic_t *excl)
{
	atomic_dec(excl);
}

/* add a request to the tail of a list */
static void req_put(struct mtp_dev *dev, struct list_head *head,
		struct usb_request *req)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	list_add_tail(&req->list, head);
	spin_unlock_irqrestore(&dev->lock, flags);
}

/* remove a request from the head of a list */
static struct usb_request *req_get(struct mtp_dev *dev, struct list_head *head)
{
	unsigned long flags;
	struct usb_request *req;

	spin_lock_irqsave(&dev->lock, flags);
	if (list_empty(head)) {
		req = 0;
	} else {
		req = list_first_entry(head, struct usb_request, list);
		list_del(&req->list);
	}
	spin_unlock_irqrestore(&dev->lock, flags);
	return req;
}

static void mtp_complete_in(struct usb_ep *ep, struct usb_request *req)
{
	struct mtp_dev *dev = _mtp_dev;

	if (req->status != 0)
		dev->error = 1;

	req_put(dev, &dev->tx_idle, req);

	wake_up(&dev->write_wq);
}

static void mtp_complete_out(struct usb_ep *ep, struct usb_request *req)
{
	struct mtp_dev *dev = _mtp_dev;

	if (req->status != 0) {
		if (!dev->flush_rx_queue)
			dev->error = 1;
		req_put(dev, &dev->rx_idle, req);
	} else
		req_put(dev, &dev->rx_done, req);

	wake_up(&dev->read_wq);
}

static void mtp_complete_notify(struct usb_ep *ep, struct usb_request *req)
{
	struct mtp_dev *dev = _mtp_dev;

	if (req->status != 0)
		dev->error = 1;
	dev->notify_in_process = 0;

	wake_up(&dev->notify_wq);
}

static int __init create_endpoints(struct mtp_dev *dev)
{
	struct usb_composite_dev *cdev = dev->cdev;
	struct usb_request *req;
	struct usb_ep *ep;
	int i;

	DBG(cdev, "create_endpoints dev: %p\n", dev);

	ep = usb_ep_autoconfig(cdev->gadget, &mtp_fs_in_desc);
	if (!ep) {
		DBG(cdev, "usb_ep_autoconfig for ep_in failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for ep_in got %s\n", ep->name);
	ep->driver_data = dev;		/* claim the endpoint */
	dev->ep_in = ep;

	ep = usb_ep_autoconfig(cdev->gadget, &mtp_fs_out_desc);
	if (!ep) {
		DBG(cdev, "usb_ep_autoconfig for ep_out failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for mtp ep_out got %s\n", ep->name);
	ep->driver_data = dev;		/* claim the endpoint */
	dev->ep_out = ep;

	ep = usb_ep_autoconfig(cdev->gadget, &mtp_fs_notify_desc);
	if (!ep) {
		DBG(cdev, "usb_ep_autoconfig for ep_out failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for mtp ep_out got %s\n", ep->name);
	ep->driver_data = dev;		/* claim the endpoint */
	dev->ep_notify = ep;

	/* now allocate requests for our endpoints */
	for (i = 0; i < REQ_MAX; i++) {
		req = mtp_request_new(dev->ep_out, BULK_BUFFER_SIZE);
		if (!req)
			goto fail;
		req->complete = mtp_complete_out;
		req_put(dev, &dev->rx_idle, req);
	}
	for (i = 0; i < REQ_MAX; i++) {
		req = mtp_request_new(dev->ep_in, BULK_BUFFER_SIZE);
		if (!req)
			goto fail;
		req->complete = mtp_complete_in;
		req_put(dev, &dev->tx_idle, req);
	}

	req = mtp_request_new(dev->ep_notify, 64);
	if (!req)
		goto fail;
	req->complete = mtp_complete_notify;
	dev->notify_req = req;
	return 0;

fail:
	while ((req = req_get(dev, &dev->tx_idle)))
		mtp_request_free(req, dev->ep_in);
	while ((req = req_get(dev, &dev->rx_idle)))
		mtp_request_free(req, dev->ep_out);
	printk(KERN_ERR "mtp: could not allocate requests\n");
	return -1;
}

static int
mtp_ctl_ioctl(struct inode *inode, struct file *fp,
	  unsigned int cmd, unsigned long arg)
{
	struct mtp_dev *dev = fp->private_data;
	struct usb_composite_dev *cdev;
	void __user *argp = (void __user *)arg;
	u32 TransactionID;
	struct usb_request *req;
	int ret;

	if (!dev)
		return -EPERM;

	cdev = dev->cdev;
	if (_lock(&dev->ctl_ioctl_excl))
		return -EBUSY;

	if (_IOC_TYPE(cmd) != USB_MTP_IOC_MAGIC) {
		printk(KERN_NOTICE "_IOC_TYPE(cmd) != USB_MTP_IOC_MAGIC\n");
		_unlock(&dev->ctl_ioctl_excl);
		return -EINVAL;
	}
	switch (cmd) {
	case MTP_IOC_GET_CANCEL_REQUEST_ID:
		DBG(cdev, "MTP_IOC_GET_CANCEL_REQUEST_ID\n");
		TransactionID = le32_to_cpu(dev->cr_data.dwTransactionID);
		if (copy_to_user(argp, &TransactionID, sizeof(__u32))) {
			_unlock(&dev->ctl_ioctl_excl);
			printk(KERN_ERR "MTP_IOC_GET_CANCEL_REQUEST_ID error\n");
			return -EFAULT;
		}
	break;
	case MTP_IOC_SET_DEVICE_STATUS:
		DBG(cdev, "MTP_IOC_SET_DEVICE_STATUS\n");
		DBG(cdev, "status = 0x%x\n", dev->dev_status);
		if (dev->dev_status == STATUS_BUSY && arg == 0x2001) {
			dev->flush_rx_queue = 1;
			usb_ep_fifo_flush(dev->ep_out);
			dev->flush_rx_queue = 0;
			while ((req = req_get(dev, &dev->rx_done)))
				req_put(dev, &dev->rx_idle, req);
			/* if we have idle read requests, get them queued */
			while ((req = req_get(dev, &dev->rx_idle))) {
				req->length = BULK_BUFFER_SIZE;
				ret = usb_ep_queue(dev->ep_out, req, GFP_ATOMIC);
				if (ret < 0) {
					printk(KERN_INFO "mtp: failed to queue req %p (%d)\n",
						req, ret);
					dev->error = 1;
					req_put(dev, &dev->rx_idle, req);
					break;
				} else
					DBG(cdev, "%s(): rx %p queue\n", __func__, req);
			}
		}
		dev->dev_status = arg;
	break;
	default:
		printk(KERN_NOTICE "%s: default\n", __func__);
		_unlock(&dev->ctl_ioctl_excl);
		return -EINVAL;
		break;
	}
	_unlock(&dev->ctl_ioctl_excl);
	return 0;
}

static ssize_t mtp_ctl_read(struct file *fp, char __user *buf,
			size_t count, loff_t *pos)
{
	struct mtp_dev *dev = fp->private_data;
	struct usb_composite_dev *cdev;
	int r = 0, n = 0, i;
	unsigned long flags;
	DBG(cdev, "%s\n", __func__);
	if (!dev)
		return -EPERM;

	cdev = dev->cdev;
	if (_lock(&dev->ctl_read_excl))
		return -EBUSY;

wait_event:
	if (wait_event_interruptible(dev->ctl_read_wq,
		(dev->event || dev->error)) < 0) {
		_unlock(&dev->ctl_read_excl);
		return -EIO;
	}
	spin_lock_irqsave(&dev->lock, flags);
	for (i = 0; i < NUM_EVENT; i++) {
		if (dev->event & (1 << i)) {
			dev->event &= ~(1 << i);
			printk(KERN_DEBUG "%s: %s\n", __func__,
				event_string[i]);
			n = strlen(event_string[i]);
			r = copy_to_user(buf, event_string[i], n);
			break;
		}
	}
	spin_unlock_irqrestore(&dev->lock, flags);
	if (i == NUM_EVENT)
		goto wait_event;

	_unlock(&dev->ctl_read_excl);
	return r? -EFAULT:n;
}

static int mtp_ctl_open(struct inode *ip, struct file *fp)
{
	if (_lock(&_mtp_dev->ctl_open_excl))
		return -EBUSY;
	printk(KERN_INFO "%s\n", __func__);
	fp->private_data = _mtp_dev;

	return 0;
}

static int mtp_ctl_release(struct inode *ip, struct file *fp)
{
	printk(KERN_INFO "%s\n", __func__);
	_unlock(&_mtp_dev->ctl_open_excl);
	return 0;
}

static struct file_operations mtp_ctl_fops = {
	.owner =	THIS_MODULE,
	.read =		mtp_ctl_read,
	.open =		mtp_ctl_open,
	.ioctl =	mtp_ctl_ioctl,
	.release =	mtp_ctl_release,
};

static struct miscdevice mtp_ctl_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "android_mtp_control",
	.fops = &mtp_ctl_fops,
};

static ssize_t mtp_event_write(struct file *fp, const char __user *buf,
			 size_t count, loff_t *pos)
{
	struct mtp_dev *dev = fp->private_data;
	struct usb_composite_dev *cdev;
	struct usb_request *req;
	int r = count;
	int ret;

	DBG(cdev, "mtp_event_write(%d)\n", count);

	if (!dev || !dev->cdev)
		return -EPERM;

	cdev = dev->cdev;

	req = dev->notify_req;
	if (!req)
		return -EIO;

	if (_lock(&dev->event_excl))
		return -EBUSY;

	if (count > MAX_EVENT_SIZE) {
		printk(KERN_INFO "too large event data(%d)\n", count);
		r = -EINVAL;
		goto err;
	}

	ret = wait_event_interruptible(dev->notify_wq,
			(!dev->notify_in_process || dev->error));
	if (dev->error) {
		r = -EIO;
		goto err;
	}

	if (copy_from_user(req->buf, buf, count)) {
		r = -EFAULT;
		goto err;
	}
	req->length = count;
	dev->notify_in_process = 1;
	ret = usb_ep_queue(dev->ep_notify, req, GFP_ATOMIC);
	if (ret < 0) {
		printk(KERN_ERR
		"send_notify_data: cannot queue status request,ret = %d\n",
			ret);
		dev->notify_in_process = 0;
		r = -EIO;
	}
err:
	_unlock(&dev->event_excl);
	return r;
}
static int mtp_event_open(struct inode *ip, struct file *fp)
{
	if (_lock(&_mtp_dev->event_open_excl))
		return -EBUSY;
	printk(KERN_INFO "%s\n", __func__);
	fp->private_data = _mtp_dev;

	return 0;
}

static int mtp_event_release(struct inode *ip, struct file *fp)
{
	printk(KERN_INFO "%s\n", __func__);
	_unlock(&_mtp_dev->event_open_excl);
	return 0;
}

static struct file_operations mtp_event_fops = {
	.owner =	THIS_MODULE,
	.write =	mtp_event_write,
	.open =		mtp_event_open,
	.release =	mtp_event_release,
};

static struct miscdevice mtp_event_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "android_mtp_event",
	.fops = &mtp_event_fops,
};

static ssize_t mtp_read(struct file *fp, char __user *buf,
				size_t count, loff_t *pos)
{
	struct mtp_dev *dev = fp->private_data;
	struct usb_composite_dev *cdev;
	struct usb_request *req;
	int r = 0, xfer;
	int ret;

	DBG(cdev, "mtp_read(%d)\n", count);

	if (!dev)
		return -EPERM;

	cdev = dev->cdev;
	if (_lock(&dev->read_excl))
		return -EBUSY;

	/* we will block until we're online */
	while (!(dev->online || dev->error)) {
		DBG(cdev, "mtp_read: waiting for online state\n");
		ret = wait_event_interruptible(dev->read_wq,
				(dev->online || dev->error));
		if (ret < 0) {
			_unlock(&dev->read_excl);
			return ret;
		}
	}

	while (count > 0) {
		if (dev->error) {
			printk(KERN_INFO "%s: -EIO\n", __func__);
			r = -EIO;
			if (dev->read_req) {
				dev->read_count = 0;
				req_put(dev, &dev->rx_idle, dev->read_req);
				dev->read_req = 0;
			}
			break;
		}

		/* if we have idle read requests, get them queued */
		while ((req = req_get(dev, &dev->rx_idle))) {
requeue_req:
			req->length = BULK_BUFFER_SIZE;
			ret = usb_ep_queue(dev->ep_out, req, GFP_ATOMIC);
			if (ret < 0) {
				printk(KERN_INFO "%s: failed to queue req %p (%d)\n",
					__func__, req, ret);
				r = -EIO;
				dev->error = 1;
				req_put(dev, &dev->rx_idle, req);
				goto fail;
			} else
				DBG(cdev, "%s(): rx %p queue\n", __func__, req);
		}

		/* if we have data pending, give it to userspace */
		if (dev->read_count > 0) {
			/* discard the data during cancel_request */
			if (dev->dev_status == STATUS_BUSY) {
				printk(KERN_DEBUG "mtp: discard data(%d) %p\n",
					dev->read_count, dev->read_req);
				dev->read_count = 0;
				req_put(dev, &dev->rx_idle, dev->read_req);
				dev->read_req = 0;
				continue;
			}
			xfer = (dev->read_count < count) ? dev->read_count : count;

			if (copy_to_user(buf, dev->read_buf, xfer)) {
				printk(KERN_ERR "%s:-EFAULT\n", __func__);
				r = -EFAULT;
				break;
			}
			dev->read_buf += xfer;
			dev->read_count -= xfer;
			buf += xfer;
			r += xfer;
			count -= xfer;

			/* if we've emptied the buffer, release the request */
			if (dev->read_count == 0) {
				req_put(dev, &dev->rx_idle, dev->read_req);
				dev->read_req = 0;
			}
			if (count && !list_empty(&dev->rx_done))
				goto read_next;
			DBG(cdev, "copy %d bytes to user\n", r);
			break;
		}
read_next:
		/* wait for a request to complete */
		req = 0;
		DBG(cdev, "%s: wait request to complete\n", __func__);
		ret = wait_event_interruptible(dev->read_wq,
			((req = req_get(dev, &dev->rx_done)) || dev->error
			|| (dev->dev_status == STATUS_BUSY)));

		if (req != 0) {
			/* if we got a 0-len one we need to put it back into
			** service.  if we made it the current read req we'd
			** be stuck forever
			*/
			if (req->actual == 0)
				goto requeue_req;

			dev->read_req = req;
			dev->read_count = req->actual;
			dev->read_buf = req->buf;
			DBG(cdev, "%s(): rx %p %d\n", __func__, req,
				req->actual);
		}

		if (ret < 0) {
			r = ret;
			break;
		}
	}

fail:
	_unlock(&dev->read_excl);
	return r;
}

static ssize_t mtp_write(struct file *fp, const char __user *buf,
				 size_t count, loff_t *pos)
{
	struct mtp_dev *dev = fp->private_data;
	struct usb_composite_dev *cdev;
	struct usb_request *req = 0;
	int r = count, xfer;
	int ret;

	DBG(cdev, "mtp_write(%d)\n", count);

	if (!dev)
		return -EPERM;

	cdev = dev->cdev;
	if (_lock(&dev->write_excl))
		return -EBUSY;

	while (count > 0) {
		if (dev->error) {
			DBG(cdev, "mtp_write dev->error\n");
			r = -EIO;
			break;
		}

		/* get an idle tx request to use */
		req = 0;
		ret = wait_event_interruptible(dev->write_wq,
			((req = req_get(dev, &dev->tx_idle)) || dev->error
			   || (dev->dev_status == STATUS_BUSY)));

		if (ret < 0) {
			r = -EIO;
			break;
		}
		if (dev->dev_status == STATUS_BUSY) {
			DBG(cdev, "mtp_write: cancel request\n");
			r = -EAGAIN;
			break;
		}

		if (req != 0) {
			if (count > BULK_BUFFER_SIZE)
				xfer = BULK_BUFFER_SIZE;
			else
				xfer = count;
			if (copy_from_user(req->buf, buf, xfer)) {
				r = -EFAULT;
				break;
			}

			req->length = xfer;
			ret = usb_ep_queue(dev->ep_in, req, GFP_ATOMIC);
			if (ret < 0) {
				DBG(cdev, "mtp_write: xfer error %d\n", ret);
				dev->error = 1;
				r = -EIO;
				break;
			}

			buf += xfer;
			count -= xfer;

			/* zero this so we don't try to free it on error exit */
			req = 0;
		}
	}

	if (req)
		req_put(dev, &dev->tx_idle, req);

	_unlock(&dev->write_excl);
	DBG(cdev, "mtp_write returning %d\n", r);
	return r;
}

static int mtp_open(struct inode *ip, struct file *fp)
{
	printk(KERN_INFO "mtp_open\n");
	if (_lock(&_mtp_dev->open_excl))
		return -EBUSY;

	fp->private_data = _mtp_dev;

	/* clear the error latch */
	_mtp_dev->error = 0;

	return 0;
}

static int mtp_release(struct inode *ip, struct file *fp)
{
	printk(KERN_INFO "mtp_release\n");
	_unlock(&_mtp_dev->open_excl);
	return 0;
}

static struct file_operations mtp_tunnel_fops = {
	.owner =   THIS_MODULE,
	.read =    mtp_read,
	.write =   mtp_write,
	.open =    mtp_open,
	.release = mtp_release,
};

static struct miscdevice mtp_tunnel_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "android_mtp_tunnel",
	.fops = &mtp_tunnel_fops,
};

static int mtp_enable_open(struct inode *ip, struct file *fp)
{
	printk(KERN_INFO "enabling mtp\n");
	android_switch_function(0x80);
	return 0;
}

static int mtp_enable_release(struct inode *ip, struct file *fp)
{
	printk(KERN_INFO "disabling mtp\n");
	android_switch_function(0x03);
	return 0;
}

static const struct file_operations mtp_enable_fops = {
	.owner =   THIS_MODULE,
	.open =    mtp_enable_open,
	.release = mtp_enable_release,
};

static struct miscdevice mtp_enable_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "android_mtp_enable",
	.fops = &mtp_enable_fops,
};

static void mtp_complete_cancel_request(struct usb_ep *ep,
		struct usb_request *req)
{
	struct mtp_dev	*dev = ep->driver_data;
	struct usb_composite_dev *cdev = dev->cdev;
	unsigned long flags;
	DBG(cdev, "Cancel_Request complete\n");

	if (req->status != 0) {
		DBG(cdev, "mtp completion, err %d\n", req->status);
		return;
	}

	/* normal completion */
	if (req->actual != sizeof(struct cancel_request_data)) {
		DBG(cdev, "mtp short resp, len %d\n",
				req->actual);
		usb_ep_set_halt(ep);
	} else {
		memcpy(&dev->cr_data, req->buf,
			sizeof(struct cancel_request_data));
		DBG(cdev, "cancel req: transaction ID = %x\n",
			dev->cr_data.dwTransactionID);
		spin_lock_irqsave(&dev->lock, flags);
		dev->event |= (1 << EVENT_CANCEL_REQUEST);
		spin_unlock_irqrestore(&dev->lock, flags);
		wake_up(&dev->ctl_read_wq);
	}
}

static int
mtp_setup(struct usb_function *f, const struct usb_ctrlrequest *ctrl)
{
	struct mtp_dev *dev = func_to_dev(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	struct usb_request	*req = cdev->req;
	int value = -EOPNOTSUPP;
	unsigned long flags;
	struct get_dev_status_data status_data;

	u16 w_index = le16_to_cpu(ctrl->wIndex);
	u16	w_value = le16_to_cpu(ctrl->wValue);
	u16 w_length = le16_to_cpu(ctrl->wLength);
	DBG(cdev, "%s, w_length=%d\n", __func__, w_length);

	switch ((ctrl->bRequestType << 8) | ctrl->bRequest) {
	case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8)
		| PIMA15740_DEVICE_RESET_REQUEST:
		DBG(cdev, "%s(): PIMA15740_DEVICE_RESET_REQUEST\n", __func__);

		spin_lock_irqsave(&dev->lock, flags);
		dev->event |= (1 << EVENT_DEVICE_RESET);
		spin_unlock_irqrestore(&dev->lock, flags);
		wake_up(&dev->ctl_read_wq);

		value = 0;
		break;
	case ((USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8)
			| PIMA15740_CANCEL_REQUEST:
		DBG(cdev, "%s(): PIMA15740_CANCEL_REQUEST\n", __func__);
		if (w_length != 6)
			break;

		dev->dev_status = STATUS_BUSY;
		wake_up(&dev->read_wq);
		wake_up(&dev->write_wq);
		value = w_length;
		cdev->gadget->ep0->driver_data = dev;
		req->complete = mtp_complete_cancel_request;
		break;
	case ((USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE) << 8)
		| PIMA15740_GET_DEVICE_STATUS:
		DBG(cdev, "%s(): PIMA15740_GET_DEVICE_STATUS(%d)\n", __func__,
			w_length);

		spin_lock_irqsave(&dev->lock, flags);
		dev->event |= (1 << EVENT_GET_DEVICE_STATUS);
		spin_unlock_irqrestore(&dev->lock, flags);
		wake_up(&dev->ctl_read_wq);

		status_data.wLength = __constant_cpu_to_le16(4);
		status_data.wCode = __constant_cpu_to_le16(dev->dev_status);
		value = sizeof(status_data);
		memcpy(req->buf, &status_data, value);
		break;

	default:
		ERROR(cdev, "invalid control req%02x.%02x v%04x i%04x l%d\n",
			ctrl->bRequestType, ctrl->bRequest,
			w_value, w_index, w_length);
	}

	/* respond with data transfer or status phase? */
	if (value >= 0) {
		DBG(cdev, "mtp req%02x.%02x v%04x i%04x l%d\n",
			ctrl->bRequestType, ctrl->bRequest,
			w_value, w_index, w_length);
		req->zero = 0;
		req->length = value;
		value = usb_ep_queue(cdev->gadget->ep0, req, GFP_ATOMIC);
		if (value < 0)
			ERROR(cdev, "mtp response err %d\n", value);
	}

	/* device either stalls (value < 0) or reports success */
	return value;
}

static int
mtp_function_bind(struct usb_configuration *c, struct usb_function *f)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct mtp_dev	*dev = func_to_dev(f);
	int			id;
	int			ret;

	dev->cdev = cdev;
	DBG(cdev, "mtp_function_bind dev: %p\n", dev);

	/* allocate interface ID(s) */
	id = usb_interface_id(c, f);
	if (id < 0)
		return id;
	mtp_interface_desc.bInterfaceNumber = id;

	/* allocate instance-specific endpoints */
	ret = create_endpoints(dev);
	if (ret)
		goto fail;

	/* support high speed hardware */
	if (gadget_is_dualspeed(c->cdev->gadget)) {
		mtp_hs_in_desc.bEndpointAddress =
			mtp_fs_in_desc.bEndpointAddress;
		mtp_hs_out_desc.bEndpointAddress =
			mtp_fs_out_desc.bEndpointAddress;
		mtp_hs_notify_desc.bEndpointAddress =
			mtp_fs_notify_desc.bEndpointAddress;
	}

	DBG(cdev, "%s speed %s: IN/%s, OUT/%s\n",
			gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full",
			f->name, dev->ep_in->name, dev->ep_out->name);
	return 0;

fail:

	/* we might as well release our claims on endpoints */
	if (dev->ep_in)
		dev->ep_in->driver_data = NULL;
	if (dev->ep_out)
		dev->ep_out->driver_data = NULL;
	if (dev->ep_notify)
		dev->ep_notify->driver_data = NULL;

	ERROR(cdev, "%s/%p: can't bind\n", f->name, f);
	return -ENODEV;
}

static void
mtp_function_unbind(struct usb_configuration *c, struct usb_function *f)
{
	struct mtp_dev	*dev = func_to_dev(f);
	struct usb_request *req;

	if (dev->ep_in)
		dev->ep_in->driver_data = NULL;
	if (dev->ep_out)
		dev->ep_out->driver_data = NULL;
	if (dev->ep_notify)
		dev->ep_notify->driver_data = NULL;
	spin_lock_irq(&dev->lock);

	mtp_request_free(dev->notify_req, dev->ep_notify);
	while ((req = req_get(dev, &dev->tx_idle)))
		mtp_request_free(req, dev->ep_in);
	while ((req = req_get(dev, &dev->rx_idle)))
		mtp_request_free(req, dev->ep_out);

	dev->online = 0;
	dev->error = 1;
	spin_unlock_irq(&dev->lock);

	misc_deregister(&mtp_tunnel_device);
	misc_deregister(&mtp_ctl_device);
	misc_deregister(&mtp_event_device);
	misc_deregister(&mtp_enable_device);
	kfree(_mtp_dev);
	_mtp_dev = NULL;
}

static int mtp_function_set_alt(struct usb_function *f,
		unsigned intf, unsigned alt)
{
	struct mtp_dev	*dev = func_to_dev(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	int ret;

	DBG(cdev, "mtp_function_set_alt intf: %d alt: %d\n", intf, alt);
	ret = usb_ep_enable(dev->ep_in,
			ep_choose(cdev->gadget,
				&mtp_hs_in_desc,
				&mtp_fs_in_desc));
	if (ret)
		return ret;
	ret = usb_ep_enable(dev->ep_out,
			ep_choose(cdev->gadget,
				&mtp_hs_out_desc,
				&mtp_fs_out_desc));
	if (ret) {
		usb_ep_disable(dev->ep_in);
		return ret;
	}

	ret = usb_ep_enable(dev->ep_notify,
			ep_choose(cdev->gadget,
				&mtp_hs_notify_desc,
				&mtp_fs_notify_desc));
	if (ret) {
		usb_ep_disable(dev->ep_in);
		usb_ep_disable(dev->ep_out);
		return ret;
	}
	dev->online = 1;
	dev->error = 0;
	if (!dev->function.hidden)
		dev->event = (1 << EVENT_ONLINE);

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);
	wake_up(&dev->ctl_read_wq);
	return 0;
}

static void mtp_function_disable(struct usb_function *f)
{
	struct mtp_dev	*dev = func_to_dev(f);
	struct usb_composite_dev	*cdev = dev->cdev;

	DBG(cdev, "mtp_function_disable (%d)\n", dev->online);
	if (dev->online)
		dev->event = (1 << EVENT_OFFLINE);
	dev->online = 0;
	dev->error = 1;
	usb_ep_disable(dev->ep_in);
	usb_ep_disable(dev->ep_out);
	usb_ep_disable(dev->ep_notify);

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);
	wake_up(&dev->notify_wq);
	wake_up(&dev->ctl_read_wq);

	VDBG(cdev, "%s disabled\n", dev->function.name);
}

static int mtp_bind_config(struct usb_configuration *c)
{
	struct mtp_dev *dev;
	int ret;

	printk(KERN_INFO "mtp_bind_config\n");

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	spin_lock_init(&dev->lock);

	init_waitqueue_head(&dev->read_wq);
	init_waitqueue_head(&dev->write_wq);
	init_waitqueue_head(&dev->ctl_read_wq);
	init_waitqueue_head(&dev->notify_wq);

	atomic_set(&dev->open_excl, 0);
	atomic_set(&dev->read_excl, 0);
	atomic_set(&dev->write_excl, 0);
	atomic_set(&dev->event_open_excl, 0);
	atomic_set(&dev->event_excl, 0);
	atomic_set(&dev->ctl_open_excl, 0);
	atomic_set(&dev->ctl_read_excl, 0);
	atomic_set(&dev->ctl_ioctl_excl, 0);

	INIT_LIST_HEAD(&dev->tx_idle);
	INIT_LIST_HEAD(&dev->rx_idle);
	INIT_LIST_HEAD(&dev->rx_done);

	ret = usb_string_id(c->cdev);
	if (ret > 0) {
		mtp_string_defs[0].id = ret;
		mtp_interface_desc.iInterface = ret;
	}

	dev->cdev = c->cdev;
	dev->function.name = "mtp";
	dev->function.strings = mtp_strings;
	dev->function.descriptors = fs_mtp_descs;
	dev->function.hs_descriptors = hs_mtp_descs;
	dev->function.bind = mtp_function_bind;
	dev->function.unbind = mtp_function_unbind;
	dev->function.set_alt = mtp_function_set_alt;
	dev->function.disable = mtp_function_disable;
	dev->function.setup = mtp_setup;
	dev->dev_status = STATUS_OK;

	/* start disabled */
	dev->function.hidden = 1;

	/* _mtp_dev must be set before calling usb_gadget_register_driver */
	_mtp_dev = dev;

	ret = misc_register(&mtp_tunnel_device);
	if (ret)
		goto err1;
	ret = misc_register(&mtp_ctl_device);
	if (ret)
		goto err2;
	ret = misc_register(&mtp_event_device);
	if (ret)
		goto err3;
	ret = misc_register(&mtp_enable_device);
	if (ret)
		goto err4;

	ret = usb_add_function(c, &dev->function);
	if (ret)
		goto err5;

	return 0;

err5:
	misc_deregister(&mtp_enable_device);
err4:
	misc_deregister(&mtp_event_device);
err3:
	misc_deregister(&mtp_ctl_device);
err2:
	misc_deregister(&mtp_tunnel_device);
err1:
	kfree(dev);
	printk(KERN_ERR "mtp gadget driver failed to initialize\n");
	return ret;
}

static struct android_usb_function mtp_function = {
	.name = "mtp",
	.bind_config = mtp_bind_config,
};

static int __init init(void)
{
	printk(KERN_INFO "f_mtp init\n");
	android_register_function(&mtp_function);
	return 0;
}
module_init(init);
