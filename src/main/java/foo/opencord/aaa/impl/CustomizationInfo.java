package foo.opencord.aaa.impl;

import org.onosproject.net.device.DeviceService;

/**
 * Bindings to Device service and Subscriber and Device Information Service
 * (SADIS), required for RADIUS packet customization.
 */
public final class CustomizationInfo {

    private final SubscriberAndDeviceInformationService subscriberService;
    private final DeviceService devService;

    /**
     * Creates a customization info instance, with bindings for the given
     * service instances.
     *
     * @param subsService subscriber service
     * @param devService device service
     */
    public CustomizationInfo(SubscriberAndDeviceInformationService subsService,
                             DeviceService devService) {
        this.subscriberService = subsService;
        this.devService = devService;
    }

    /**
     * Returns the reference to the subscriber service.
     *
     * @return the subscriber service
     */
    public SubscriberAndDeviceInformationService subscriberService() {
        return subscriberService;
    }

    /**
     * Returns the reference to the device service.
     *
     * @return the device service
     */
    public DeviceService deviceService() {
        return devService;
    }
}
