/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ESP_CTL_H
#define ESP_CTL_H 1

/* Control interface for an IKE daemon, such as strongSwan with its
 * "kernel-ovs" plugin, to install the security associations of 'esp'
 * tunnels with "esp_keying=ike" through unixctl commands. */

#include <stdint.h>

struct ds;

void esp_ctl_init(void);
void esp_ctl_format(struct ds *, uint32_t if_id);

#endif /* esp-ctl.h */
