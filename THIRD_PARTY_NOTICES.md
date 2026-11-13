# Third-party components

The repository's Apache-2.0 license applies to its original code and documentation. Third-party software keeps its own copyright and license terms. This file identifies direct dependencies and upstream references; it does not replace their license texts or an inventory of a particular container image.

This repository distributes build/deployment instructions and original source. It does not vendor the upstream executables, container layers, generated credentials or runtime databases. Building these instructions downloads additional software. Publishing the source repository and publishing built images are separate release activities.

## Direct components

| Component | Version/source used by this repository | Upstream license and notices |
| --- | --- | --- |
| Xray-core | `v26.11.9`, downloaded release executables | [Mozilla Public License 2.0](https://github.com/XTLS/Xray-core/blob/v26.11.9/LICENSE). [Matching source](https://github.com/XTLS/Xray-core/tree/v26.11.9). |
| Tailscale CLI and daemon | `v1.104.5`, official static Linux archives | [BSD-3-Clause](https://github.com/tailscale/tailscale/blob/v1.104.5/LICENSE), copyright Tailscale Inc. and contributors. The release also has [third-party dependency notices](https://github.com/tailscale/tailscale/blob/v1.104.5/licenses/tailscale.md); these are additional to its root license. |
| 3x-ui | `v3.11.0`, application files copied from its upstream container | [GNU GPL version 3](https://github.com/MHSanaei/3x-ui/blob/v3.11.0/LICENSE). [Matching source](https://github.com/MHSanaei/3x-ui/tree/v3.11.0). Bundled frontend, protocol engines, data files and other dependencies retain their own notices. |
| Headscale | `v0.29.7`, executable copied from its upstream container | [BSD-3-Clause](https://github.com/juanfont/headscale/blob/v0.29.7/LICENSE), copyright Juan Font and contributors. [Matching source](https://github.com/juanfont/headscale/tree/v0.29.7). |
| musl libc | Runtime loader/library copied from the selected 3x-ui container; exact package version follows that image | [musl copyright and license information](https://git.musl-libc.org/cgit/musl/tree/COPYRIGHT). MIT overall, with additional permissive notices for incorporated code. Retain the notices corresponding to the actual copied version. |
| yaml-cpp | Debian `libyaml-cpp-dev` / `libyaml-cpp0.8` packages | [MIT](https://github.com/jbeder/yaml-cpp/blob/0.8.0/LICENSE), copyright Jesse Beder and contributors. Exact package revisions and Debian changes are identified by the installed package metadata. |
| nlohmann/json | Debian `nlohmann-json3-dev`, headers compiled into `node-agent` | [MIT](https://github.com/nlohmann/json/blob/v3.11.3/LICENSE.MIT), copyright Niels Lohmann and contributors. Its notice must accompany redistribution of the compiled agent as applicable. |
| curl and libcurl | Debian `curl`, `libcurl4-openssl-dev` / `libcurl4t64` packages | [curl license](https://curl.se/docs/copyright.html), copyright Daniel Stenberg and contributors; this is its own permissive license, not the standard MIT text. |
| Tini | Debian `tini` package | [MIT](https://github.com/krallin/tini/blob/v0.19.0/LICENSE), copyright Thomas Orozco and contributors. |
| nginx | Debian `nginx-light` and dependency packages | [BSD-2-Clause-style upstream license](https://github.com/nginx/nginx/blob/master/LICENSE), copyright Igor Sysoev, Nginx, Inc. and contributors. The installed Debian package records the applicable version and notices. |
| Debian base images and packages | `debian:stable-slim`; the package set follows Debian stable/security repositories | Debian is a distribution of independently licensed packages, not one software license. See [Debian license information](https://www.debian.org/legal/licenses/) and the installed `/usr/share/doc/<package>/copyright` and `/usr/share/common-licenses` files. This includes libc, compiler runtime libraries, TLS libraries, networking tools and their dependencies. |
| Ansible Core | `2.19.15`, controller dependency | [GPL-3.0-or-later](https://github.com/ansible/ansible/blob/v2.19.15/lib/ansible/__init__.py); [license text](https://github.com/ansible/ansible/blob/v2.19.15/COPYING). Installed in the controller environment, not vendored here. |
| `containers.podman` Ansible collection | `1.18.0`, controller dependency | [GPL-3.0-or-later declaration](https://github.com/containers/ansible-podman-collections/blob/1.18.0/galaxy.yml) and [license text](https://github.com/containers/ansible-podman-collections/blob/1.18.0/COPYING). Installed separately, not vendored here. |
| Python test runtime | Official `python:3.13-slim` image used by the HTTP witness | [Python license information](https://docs.python.org/3.13/license.html), plus the independently licensed Debian packages in that image. |

The optional single-client image builds 3x-ui from commit `c621ba9014a6aa21fd7c9ecf45655e44e24ebf13` with repository patches for route selector import, literal subscription labels, account eligibility, and preservation of Vision when a detached client rejoins its first inbound. The changes to 3x-ui are provided under its GPLv3 license. The build recipe verifies the source archive and includes the upstream license in the image. [Matching source](https://github.com/MHSanaei/3x-ui/tree/c621ba9014a6aa21fd7c9ecf45655e44e24ebf13), [local patches](infra/3x-ui/), [build instructions](infra/Dockerfile.control.single).

Versioned links above identify the selected upstream releases where practical. Debian package versions, musl, nginx and image layers must be recorded from the exact built image; the rolling `stable-slim` tag is not a reproducible version identifier.

## GeoIP and GeoSite assets

`infra/download.sh` copies `geoip.dat` and `geosite.dat` from the selected Xray release archive. These data files are separate from the Xray executable and must not be assumed to be covered solely by Xray's MPL license.

The [Xray `v26.11.9` asset workflow](https://github.com/XTLS/Xray-core/blob/v26.11.9/.github/workflows/scheduled-assets-update.yml) obtains GeoIP Lite and GeoSite assets from [XTLS/Xray-rules-dat](https://github.com/XTLS/Xray-rules-dat). That project's [source and license documentation](https://github.com/XTLS/Xray-rules-dat#source-code-and-licenses) identifies GPLv3 for the project as a whole, separate [MIT GeoSite terms](https://github.com/XTLS/Xray-rules-dat/blob/main/LICENSE-GeoSite) and [inherited terms](https://github.com/XTLS/Xray-rules-dat/blob/main/LICENSE-GeoSite-inherit). Its GeoIP and GeoSite branches document additional input sources. Record the actual data revision, applicable input-data terms and required attribution when redistributing an archive or image containing these assets. A current branch README is not a complete notice bundle for an older binary artifact.

## Built-image publication status

The current build files are designed for local builds. They do not yet produce a complete third-party notice/source bundle suitable for asserting that a container-image release is distribution-ready:

- `infra/download.sh` selects executables and `.dat` files from release archives without retaining all accompanying licenses and notices.
- `infra/Dockerfile.headscale` selects the Headscale executable without copying its license materials.
- `infra/Dockerfile.control` selects `/app` and musl runtime files; those paths alone do not establish that the image includes all 3x-ui, musl, frontend, bundled-engine and data-source notices.
- Debian package copyright materials cover Debian-installed packages; they do not automatically cover executables and libraries copied from other images or downloaded archives.

Before publishing built images, include the applicable full license/copyright notices and transitive dependency notices for the exact artifacts. For GPL-covered executables such as 3x-ui, accompany the release with the corresponding-source access and directions required by [GPLv3 section 6](https://www.gnu.org/licenses/gpl-3.0.html#section6), including relevant build material. For MPL-covered executables, provide the covered source and source-access directions required by [MPL 2.0 section 3.2](https://www.mozilla.org/en-US/MPL/2.0/). Preserve the BSD/MIT/curl notices and disclaimers that accompany binary distributions. A table of project links is not a substitute for these materials.

Create a package/artifact inventory for each published image digest, retain Debian copyright files, and resolve the GeoIP/GeoSite input-data notices. Review upstream Go/frontend dependency notices as well as the direct projects listed here. Do not describe a future image release as entirely Apache-2.0: that license does not replace the licenses of included third-party programs, libraries or data.
