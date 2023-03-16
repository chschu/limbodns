package net.limbomedia.dns.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpHeader;
import org.kuhlins.webkit.HttpUtils;
import org.kuhlins.webkit.HttpUtils.UserAndPass;
import org.kuhlins.webkit.ex.NotFoundException;
import org.kuhlins.webkit.ex.ValidationException;

import net.limbomedia.dns.ZoneManager;
import net.limbomedia.dns.model.Config;
import net.limbomedia.dns.model.UpdateResult;

/**
 * Supports the <a href="https://help.dyn.com/remote-access-api/">DynDNS2</a> protocol.
 * <p>
 * The HTTP basic authentication password contains one or more comma-separated update tokens.
 * </p>
 * <p>
 * The request parameter <em>hostname</em> contains one or more comma-separated hostnames.
 * </p>
 * <p>
 * The request parameter <em>myip</em> contains zero or more comma-separated IP addresses.
 * </p>
 * <p>
 * The protocol specifies that the response must contain the update results for each
 * hostname specified in the <em>hostname</em> request header, in the order given.
 * There might be records that do match one of the update tokens, but are not specified
 * in the <em>hostname</em> request parameter. These records will still be updated, but
 * they will not be reported in the response.
 * </p>
 */
public class DynDNS2UpdateServlet extends ServletGeneric {

	private static final long serialVersionUID = 1L;

	private ZoneManager zoneManager;

	private Config config;

	public DynDNS2UpdateServlet(Config config, ZoneManager zoneManager) {
		this.config = config;
		this.zoneManager = zoneManager;
		handlers.add(this::handleUpdate);
	}

	private boolean handleUpdate(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		String joinedReturnCodes = update(req).stream()
				.collect(Collectors.joining("\n", "", "\n"));
		resp.getOutputStream().write(joinedReturnCodes.getBytes(StandardCharsets.UTF_8));
		return true;
	}

	private List<String> update(HttpServletRequest req) {
		UserAndPass uap = HttpUtils.parseBasicAuth(req.getHeader(HttpHeader.AUTHORIZATION.asString()));

		String hostnameParam = req.getParameter("hostname");
		String myipParam = req.getParameter("myip");
		if (uap == null || uap.getPass().isEmpty() || hostnameParam == null || hostnameParam.isEmpty()) {
			return List.of("badagent");
		}

		String remoteAddress = HttpUtils.remoteAdr(req, config.getRemoteAddressHeader());
		if (myipParam == null || myipParam.isEmpty()) {
			myipParam = remoteAddress;
		}

		// map hostnames (in the given order) and record types (A/AAAA) to update result
		Map<String, Map<String, UpdateResult>> updateResultByHostnameAndRecordType = new LinkedHashMap<>();
		for (String hostname : hostnameParam.split(",")) {
			updateResultByHostnameAndRecordType.put(hostname, new LinkedHashMap<>());
		}

		// myip may contain multiple IP addresses (to update IPv4 and IPv6 records)
		for (String myip : myipParam.split(",")) {
			// password may contain multiple tokens (to update IPv4 and IPv6 records)
			for (String token : uap.getPass().split(",")) {
				try {
					// collect update results for hostnames of updated A/AAAA records
					for (UpdateResult result : zoneManager.recordDynDNS(remoteAddress, token, myip)) {
						Map<String, UpdateResult> updateResultByRecordType = updateResultByHostnameAndRecordType.get(getUpdatedHostname(result));
						String recordType = result.getType();
						if (updateResultByRecordType != null && ("A".equals(recordType) || "AAAA".equals(recordType))) {
							updateResultByRecordType.put(recordType, result);
						}
					}
				} catch (NotFoundException | ValidationException e) {
					// nothing updated by this combination of token and IP address
				}
			}
		}

		// convert collected update results to return codes
		Map<String, String> returnCodeByHostname = new LinkedHashMap<>();
		for (Map.Entry<String, Map<String, UpdateResult>> entry : updateResultByHostnameAndRecordType.entrySet()) {
			String hostname = entry.getKey();
			Map<String, UpdateResult> updateResultByRecordType = entry.getValue();
			if (updateResultByRecordType.isEmpty()) {
				// nothing updated for this hostname
				returnCodeByHostname.put(hostname, "nohost");
			} else {
				// at least one record updated
				boolean changed = updateResultByRecordType.values().stream().anyMatch(UpdateResult::isChanged);
				String ips = updateResultByRecordType.values().stream().map(UpdateResult::getValue).collect(Collectors.joining(","));
				returnCodeByHostname.put(hostname, (changed ? "good " : "nochg ") + ips);
			}
		}

		return List.copyOf(returnCodeByHostname.values());
	}

	private String getUpdatedHostname(UpdateResult updateResult) {
		String record = updateResult.getRecord();
		String zone = updateResult.getZone();
		String domain = zone.substring(0, zone.length() - 1);
		if ("@".equals(record)) {
			return domain;
		}
		if (record.endsWith(".")) {
			return record.substring(0, record.length() - 1);
		}
		return record + "." + domain;
	}
}
