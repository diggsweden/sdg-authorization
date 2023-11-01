package se.digg.sdg.samples.directaccessclient.components;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class ScheduledFetch {

    private final AccessTokenLoadingCache accessTokenCache;
    private final RestTemplate template;

    public ScheduledFetch(AccessTokenLoadingCache accessTokenCache, RestTemplate template) {
        this.accessTokenCache = accessTokenCache;
        this.template = template;
    }

    /**
     * Fetches and prints evidence from evidence service 3 once a minute with no user involvement
     */
    @Scheduled(cron = "0 * * * * *")
    public void updateEvidence() {

        log.info("Fetching information from EvicendeService");
        try {
            String token = accessTokenCache.getAccessToken();
            String header = "Bearer " + token;
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", header);
            HttpEntity<String> entity = new HttpEntity<>("body", headers);
            String response = template.exchange("https://localhost:8446/evidence/service3", HttpMethod.GET, entity, String.class).getBody();
            log.info(response);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
