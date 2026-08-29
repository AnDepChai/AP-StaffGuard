package com.anpahn.staffguard.util;

import com.anpahn.staffguard.config.StaffGuardConfig;
import com.anpahn.staffguard.model.ProxyMode;
import org.bukkit.entity.Player;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

import java.net.InetAddress;

public final class ClientIpResolver {
    private final StaffGuardConfig config;
    private final IpMatcher trustedProxies;

    public ClientIpResolver(StaffGuardConfig config) {
        this.config=config;
        this.trustedProxies=new IpMatcher(config.trustedProxyAddresses());
    }

    public Resolution resolve(AsyncPlayerPreLoginEvent event) {
        InetAddress raw=event.getRawAddress();
        InetAddress forwarded=event.getAddress();
        return resolve(raw,forwarded);
    }

    public Resolution resolve(InetAddress rawAddress, InetAddress forwardedAddress) {
        if (config.proxyMode()==ProxyMode.NONE) {
            if (rawAddress == null || forwardedAddress == null) return Resolution.invalid("client address unavailable");
            if (!rawAddress.equals(forwardedAddress)) return Resolution.invalid("forwarded client address differs from the raw transport address; configure a trusted proxy mode");
            return valid(rawAddress);
        }
        if (rawAddress == null || !trustedProxies.isAllowed(rawAddress)) return Resolution.invalid("untrusted proxy connection");
        if (forwardedAddress == null) return Resolution.invalid("forwarded client address unavailable");
        return valid(forwardedAddress);
    }

    public Resolution resolvePlayer(Player player) {
        if (config.proxyMode()!=ProxyMode.NONE) return Resolution.invalid("manual player IP resolution is disabled behind a proxy because the raw transport address is unavailable");
        if (player == null || player.getAddress() == null) return Resolution.invalid("player address unavailable");
        return valid(player.getAddress().getAddress());
    }

    private Resolution valid(InetAddress address) {
        String normalized=IpAddressUtil.normalizeLiteral(address.getHostAddress());
        if (normalized==null || !IpAddressUtil.isUsableUnicastLiteral(normalized)) return Resolution.invalid("client address is not a usable unicast literal");
        return new Resolution(true,normalized,null);
    }

    public record Resolution(boolean valid,String ip,String reason) {
        static Resolution invalid(String reason){return new Resolution(false,null,reason);}
    }
}
