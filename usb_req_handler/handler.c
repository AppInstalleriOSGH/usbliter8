#include <stdint.h>
#include <stdlib.h>
#include "offsets.h"

#define USB_DIRECTION_MASK  0x80
#define USB_DEVICE2HOST     0x80
#define USB_HOST2DEVICE     0x00

#define EP0_IN  0x80

struct usb_device_request {
    uint8_t  bmRequestType;
    uint8_t  bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
} __attribute__((packed));

enum {
    DFU_DETACH = 0,
    DFU_DNLOAD,
    DFU_UPLOAD,
    DFU_GETSTATUS,
    DFU_CLR_STATUS,
    DFU_GETSTATE,
    DFU_ABORT,
    CUSTOM_DEMOTE,
    CUSTOM_BOOT,
    CUSTOM_ARB_CALL
};

static int  (*orig_handle_usb_req)(struct usb_device_request *request, uint8_t **io_buffer) = (void *)HANDLE_USB_REQ;
static void (*platform_demote)() = (void *)PLATFORM_DEMOTE;
static void (*platform_set_remote_boot)() = (void *)PLATFORM_SET_REMOTE_BOOT;

#ifdef USB_CORE_DO_TRANSFER
static void (*usb_core_do_transfer)(uint32_t endpoint, void *io_buffer, uint32_t io_length, void *callback) = (void*)USB_CORE_DO_TRANSFER;
#endif

#if WITH_PAC

__attribute__((naked))
uint64_t PACIB(uint64_t ptr, uint64_t ctx) {
    asm("PACIB x0, x1");
    asm("RET");
}

#endif

int custom_handle_usb_req(struct usb_device_request *request, uint8_t **io_buffer) {
    uint8_t bmRequestType = request->bmRequestType;
    uint8_t bRequest      = request->bRequest;
    
#if defined(USB_CORE_DO_TRANSFER) && defined(INSECURE_MEMORY_BASE)
    if ((bmRequestType & USB_DIRECTION_MASK) == USB_DEVICE2HOST) {
        switch (bRequest) {
            // doesn't like to work with the other handlers that's why they're gone.
            case CUSTOM_ARB_CALL: {
                uint64_t* payload = (void*)INSECURE_MEMORY_BASE;
                uint64_t (*func)(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6, uint64_t x7) = 0;
                func = (void*)payload[0];
                uint64_t ret = func(payload[2], payload[3], payload[4], payload[5], payload[6], payload[7], payload[8], payload[9]);
                payload[1] = ret;
                usb_core_do_transfer(0x80, payload, request->wLength, 0);
                return 0;
            }
        }
    }
#endif
    /* everything that doesn't fall under the conditions above goes to the original handler */
    return orig_handle_usb_req(request, io_buffer);
}
