![CrowdSec Logo](images/logo_crowdsec.png)

# OpenCTI CrowdSec internal enrichment connector

## User Guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Description

This is a OpenCTI connector which enriches your knowledge by using CrowdSec's CTI API.

Architecturally it is an independent python process which has access to the OpenCTI instance and CrowdSec's CTI API. 
It enriches knowledge about every incoming IP in OpenCTI by looking it up in CrowdSec CTI.

### Configuration

Configuration parameters are provided using environment variables as described below. Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once that they have been defined by the developer of the connector.



#### Parameters meaning

| Docker environment variable | Mandatory | Type | Description                                                                                                                                                |
| ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `OPENCTI_URL`  | Yes  | String    | The URL of the OpenCTI platform.                                                                                                                           |
| `OPENCTI_TOKEN` | Yes          | String  | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `CONNECTOR_ID`  | Yes          | String    | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `CONNECTOR_NAME` | Yes          | String    | Name of the CrowdSec connector to be shown in OpenCTI.                                                                                  |
| `CONNECTOR_SCOPE` | Yes          | String    | Supported scope: `IPv4-Addr`                                                                                   |
| `CONNECTOR_CONFIDENCE_LEVEL` | Yes          | Integer | The default confidence level  (an integer between 0 and 100).                                                                |
| `CONNECTOR_AUTO` | No | Boolean | Enable/disable auto-enrichment of observables. Default: `false` |
| `CONNECTOR_LOG_LEVEL` | No         | String    | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). Default: `info`                                          |
| `CROWDSEC_KEY`   | Yes       | String | CrowdSec CTI  API key. See [instructions to obtain it](https://docs.crowdsec.net/docs/next/cti_api/getting_started/#getting-an-api-key)                                                                         |
| `CROWDSEC_API_VERSION` | No | String | CrowdSec API version. Supported version: `v2`. Default: `v2`. |
| `CROWDSEC_MAX_TLP` | No     | String | Do not send any data to CrowdSec if the TLP of the observable is greater than `crowdsec_max_tlp`. Default: `TLP:AMBER` |
| `CROWDSEC_NAME` | No     | String | The CrowdSec organization name. Default: `CrowdSec`                                                         |
| `CROWDSEC_DESCRIPTION` | No     | String | The CrowdSec organization description. Default: `CrowdSec CTI enrichment`                                   |
| `CROWDSEC_LABELS_SCENARIO_USE` | No | Boolean | Enable/disable labels creation based on CTI scenario. Default: `true` |
| `CROWDSEC_LABELS_SCENARIO_ONLY_NAME` | No | Boolean | CTI scenario has a label and a name part. You can set here to use only name part. Default: `false` |
| `CROWDSEC_LABELS_SCENARIO_COLOR` | No | String | Color of scenario based labels. Default: `#2E2A14` ![](./images/labels/2E2A14.png) |
| `CROWDSEC_LABELS_CVE_USE` | No | Boolean | Enable/Disable CTI cve name based labels. Default: `false` |
| `CROWDSEC_LABELS_CVE_COLOR` | No | String | Color of cve based labels. Default: `#800080` ![](./images/labels/800080.png) |
| `CROWDSEC_LABELS_MITRE_USE` | No | Boolean | Enable/Disable CTI mitre technique based labels. Default: `false` |
| `CROWDSEC_LABELS_MITRE_COLOR` | No | String | Color of mitre technique based labels. Default: `#000080` ![](./images/labels/000080.png) |
| `CROWDSEC_LABELS_BEHAVIOR_USE` | No | Boolean | Enable/Disable CTI behavior based labels. Default: `false` |
| `CROWDSEC_LABELS_BEHAVIOR_COLOR` | No | String | Color of behavior based labels. Default: `#808000` ![](./images/labels/808000.png) |
| `CROWDSEC_LABELS_REPUTATION_USE` | No | Boolean | Enable/Disable CTI reputation based labels. Default: `false` |
| `CROWDSEC_LABELS_REPUTATION_MALICIOUS_COLOR` | No | String | Color of malicious reputation label. Default: `#FF0000` ![](./images/labels/FF0000.png) |
| `CROWDSEC_LABELS_REPUTATION_SUSPICIOUS_COLOR` | No | String | Color of suspicious reputation label. Default: `#FFA500` ![](./images/labels/FFA500.png) |
| `CROWDSEC_LABELS_REPUTATION_SAFE_COLOR` | No | String | Color of safe reputation label. Default: `#00BFFF` ![](./images/labels/00BFFF.png) |
| `CROWDSEC_LABELS_REPUTATION_KNOWN_COLOR` | No | String | Color of safe reputation label. Default: `#808080` ![](./images/labels/808080.png) |
| `CROWDSEC_INDICATOR_CREATE_FROM` | No | String | List of reputations to create indicators from (malicious, suspicious, known, safe) separated by comma. Default: empty `''`. If an IP is detected with a reputation that belongs to this list, an indicator based on the observable will be created. |
| `CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE` | No | Boolean | Create attack patterns from MITRE techniques (available only if indicator is created depending on the above ``CROWDSEC_INDICATOR_CREATE_FROM` setting). Default `true` |
| `CROWDSEC_CREATE_NOTE` | No | Boolean | Enable/disable creation of a note in observable for each enrichment. Default: `false` |
| `CROWDSEC_CREATE_SIGHTING` | No | Boolean | Enable/disable creation of a sighting. Default: `true` |

You could also use the `config.yml`file of the connector to set the variable.  

In this case, please put the variable name in lower case and separate it into 2 parts using the first underscore `_`. For example, the docker setting `CROWDSEC_MAX_TLP=TLP:AMBER` becomes : 

```yaml
crowdsec:
	max_tlp: 'TLP:AMBER'
```

You will find a `config.yml.sample` file as example.



#### Recommended settings



  - CROWDSEC_LABELS_SCENARIO_USE=true
  - CROWDSEC_LABELS_SCENARIO_ONLY_NAME=false
  - CROWDSEC_LABELS_CVE_USE=true
  - CROWDSEC_LABELS_REPUTATION_USE=true
  - CROWDSEC_INDICATOR_CREATE_FROM='malicious,suspicious,known'
  - CROWDSEC_CREATE_NOTE=true



### Use case: enrich an observable

If you create an `IPv4 address` observable, this connector will enable you to enrich it with data retrieved from CrowdSec's CTI. 

If `CONNECTOR_AUTO` configuration is set to `true`, the observable will be automatically enriched when created. Otherwise, you'll need to enrich it manually by clicking on the enrichment icon and selecting the CrowdSec connector.



### Additional information

This connector will lookup and edit incoming `IPv4-Addr` observable entity.
Note that CrowdSec's CTI has quotas, this connector will poll it if quota is exceeded following exponential backoff.
