package foo.opencord.olt.impl;

import foo.opencord.aaa.api.AaaService;
import foo.opencord.aaa.api.PacketCustomizer;
import foo.opencord.aaa.impl.CustomizationInfo;
import foo.opencord.olt.api.AccessDeviceData;
import foo.opencord.olt.api.AccessDeviceEvent;
import foo.opencord.olt.api.AccessDeviceListener;
import foo.opencord.olt.api.AccessDeviceService;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;
import org.onlab.packet.VlanId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.AbstractListenerManager;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.device.DeviceService;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;

import java.util.Collection;
import java.util.Map;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * A skeleton sketch of the OLT application...
 */
@Service
@Component(immediate = true)
public class Olt
        extends AbstractListenerManager<AccessDeviceEvent, AccessDeviceListener>
        implements AccessDeviceService {

    private static final String APP_NAME = "org.opencord.olt";

    private final Logger log = getLogger(getClass());

    // ...

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected SubscriberAndDeviceInformationService subsService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected AaaService aaaService;

    // ...

    private ApplicationId appId;

    private CustomizationInfo custInfo;

    private PacketCustomizer pktCustomizer;

    @Activate
    public void activate(ComponentContext context) {

        appId = coreService.registerApplication(APP_NAME);

        custInfo = new CustomizationInfo(subsService, deviceService);
        pktCustomizer = new SamplePacketCustomizer(custInfo);

        // ...

        aaaService.registerPacketCustomizer(pktCustomizer);

        // ...

        log.info("Started with Application ID {}", appId.id());
    }

    @Deactivate
    public void deactivate() {

        // ...

        aaaService.unregisterPacketCustomizer(pktCustomizer);

        // ...

        log.info("Stopped");
    }

    @Override
    public void provisionSubscriber(ConnectPoint port, VlanId vlan) {

    }

    @Override
    public void removeSubscriber(ConnectPoint port) {

    }

    @Override
    public Collection<Map.Entry<ConnectPoint, VlanId>> getSubscribers() {
        return null;
    }

    @Override
    public Map<DeviceId, AccessDeviceData> fetchOlts() {
        return null;
    }
}
