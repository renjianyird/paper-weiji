// Copyright (C) 2025 Langning Chen
//
// This file is part of paper.
//
// paper is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// paper is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with paper.  If not, see <https://www.gnu.org/licenses/>.

#include "define.hpp"
#include "capture.hpp"
#include "io.hpp"
#include "i18n.hpp"
#include <ntddndis.h>
#include "json.hpp"
// 新增头文件：用于IP地址格式化
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// 为了方便使用，可以添加一个别名
using json = nlohmann::json;

CAPTURE::CAPTURE_RESULT *CAPTURE::global_capture_result = nullptr;
pcap_t *CAPTURE::global_pcap_handle = nullptr;

void CAPTURE::packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    IO::Debug(t("packet_received") + ": " + std::to_string(header->len));
    if (CAPTURE::IsWantedRequest(pkt_data, header->len, *CAPTURE::global_capture_result))
    {
        IO::Debug(t("target_packet_found"));
        pcap_breakloop(CAPTURE::global_pcap_handle);
    }
}

bool CAPTURE::IsWantedRequest_NetworkLayer(const u_char **buf, int &len)
{
    if (len < sizeof(eth_header) + sizeof(ip_header))
    {
        IO::Debug(t("packet_too_small_network"));
        return false;
    }
    const eth_header *eh = (const eth_header *)*buf;
    if (ntohs(eh->ether_type) != 0x0800)
    {
        IO::Debug(t("non_ipv4_packet"));
        return false;
    }
    *buf += sizeof(eth_header);
    len -= sizeof(eth_header);
    const ip_header *ih = (const ip_header *)*buf;
    if ((ih->ip_hl_v & 0xF0) != 0x40)
    {
        IO::Debug(t("non_ipv4_packet_header"));
        return false;
    }
    if ((ih->ip_p) != IPPROTO_TCP)
    {
        IO::Debug(t("non_tcp_packet"));
        return false;
    }
    const size_t deltaLen = (ih->ip_hl_v & 0x0F) * 4;
    *buf += deltaLen;
    len -= deltaLen;
    IO::Debug(t("network_layer_passed"));
    return true;
}

bool CAPTURE::IsWantedRequest_TransportLayer(const u_char **buf, int &len)
{
    if (len < sizeof(tcp_header))
    {
        IO::Debug(t("packet_too_small_transport"));
        return false;
    }
    const tcp_header *th = (const tcp_header *)*buf;
    if ((th->th_offx2 & 0xF0) == 0)
    {
        IO::Debug(t("invalid_tcp_header"));
        return false;
    }
    if (ntohs(th->th_sport) != 80 && ntohs(th->th_dport) != 80)
    {
        IO::Debug(t("non_http_port") + "=" + std::to_string(ntohs(th->th_sport)) + " " + t("dst") + "=" + std::to_string(ntohs(th->th_dport)));
        return false;
    }
    const size_t deltaLen = ((th->th_offx2 & 0xF0) >> 4) * 4;
    *buf += deltaLen;
    len -= deltaLen;
    IO::Debug(t("transport_layer_passed") + ": " + std::to_string(len) + " " + t("bytes"));
    return true;
}

bool CAPTURE::IsWantedRequest(const u_char *pkt_data, int data_len, CAPTURE_RESULT &result)
{
    IO::Debug(t("analyzing_packet") + " " + std::to_string(data_len) + " " + t("bytes"));
    if (!IsWantedRequest_NetworkLayer(&pkt_data, data_len) ||
        !IsWantedRequest_TransportLayer(&pkt_data, data_len) ||
        !data_len)
    {
        IO::Debug(t("packet_rejected"));
        return false;
    }

    const std::string payload((char *)pkt_data, data_len);
    std::smatch matches;
    const std::regex pattern(R"(^POST (/product/[0-9]+/[0-9a-f]+/ota/checkVersion) HTTP/[0-9.]+\r\n([^\r\n]*\r\n)*\r\n(.*)$)");
    IO::Debug(t("http_payload_preview") + ": " + payload.substr(0, std::min(200, (int)payload.length())));
    if (std::regex_search(payload, matches, pattern))
    {
        IO::Debug(t("ota_request_matched"));
        result.productUrl = matches[1].str();
        IO::Debug(t("product_url") + ": " + result.productUrl);
        try
        {
            result.request_body = nlohmann::json::parse(matches[3].str());
            IO::Debug(t("json_body_parsed"));
        }
        catch (const nlohmann::json::parse_error &e)
        {
            DIE(t("failed_parse_json") + ": " + std::string(e.what()));
        }
        return true;
    }
    IO::Debug(t("ota_request_not_matched"));
    return false;
}

void CAPTURE::capture(CAPTURE_RESULT &result)
{
    IO::Debug(t("initializing_capture"));
    char errbuf[PCAP_ERRBUF_SIZE];
    global_capture_result = &result;
    global_pcap_handle = nullptr;

    IO::Debug(t("finding_devices"));
    pcap_if_t *devices;
    if (pcap_findalldevs(&devices, errbuf) == -1)
        DIE(t("error_finding_devices") + ": " + std::string(errbuf));

    IO::Debug(t("searching_hotspot"));
    pcap_if_t *selectedDevice = nullptr;
    // 优化：遍历所有网卡，匹配192.168.137.x网段（不局限于192.168.137.1）
    for (pcap_if_t *device = devices; device && !selectedDevice; device = device->next)
    {
        IO::Debug(t("checking_device") + ": " + std::string(device->name ? device->name : "unknown"));
        for (pcap_addr_t *addr = device->addresses; addr && !selectedDevice; addr = addr->next)
        {
            if (addr->addr && addr->addr->sa_family == AF_INET)
            {
                struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)addr->addr;
                char ip_str[INET_ADDRSTRLEN];
                // 格式化IP地址为字符串（如192.168.137.1）
                inet_ntop(AF_INET, &(ipv4_addr->sin_addr), ip_str, INET_ADDRSTRLEN);
                
                // 核心修改：匹配192.168.137.x整个网段，而非仅192.168.137.1
                if (strncmp(ip_str, "192.168.137.", 10) == 0)
                {
                    IO::Debug(t("found_target_interface") + ": " + std::string(device->name) + " (IP: " + ip_str + ")");
                    selectedDevice = device;
                }
            }
        }
    }

    // 未找到热点网卡时，先释放资源再退出
    if (!selectedDevice)
    {
        pcap_freealldevs(devices); // 修复原代码内存泄漏问题
        DIE(t("no_interface_found") + " (请确保开启移动热点，且网卡IP为192.168.137.x)");
    }

    IO::Debug(t("opening_capture_handle") + ": " + std::string(selectedDevice->name));
    pcap_t *packetCaptureHandle = pcap_open_live(selectedDevice->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, errbuf);
    if (packetCaptureHandle == NULL)
    {
        pcap_freealldevs(devices); // 修复原代码内存泄漏问题
        DIE(t("unable_open_adapter") + ": " + errbuf);
    }
    global_pcap_handle = packetCaptureHandle;
    
    IO::Debug(t("checking_datalink"));
    if (pcap_datalink(packetCaptureHandle) != DLT_EN10MB)
        IO::Warn(t("non_ethernet_link"));

    IO::Debug(t("setting_packet_filter"));
    u_int netmask = 0xffffff00; // 显式设置默认子网掩码（避免空指针）
    if (selectedDevice->addresses != NULL && selectedDevice->addresses->netmask != NULL)
        netmask = ((struct sockaddr_in *)(selectedDevice->addresses->netmask))->sin_addr.S_un.S_addr;

    struct bpf_program fcode;
    std::string pcap_filter_string = "tcp port 80";
    IO::Debug(t("compiling_filter") + ": " + pcap_filter_string);
    if (pcap_compile(packetCaptureHandle, &fcode, pcap_filter_string.c_str(), 1, netmask) < 0)
    {
        pcap_close(packetCaptureHandle);
        pcap_freealldevs(devices);
        DIE(t("unable_compile_filter") + ": " + std::string(pcap_geterr(packetCaptureHandle)));
    }
    
    IO::Debug(t("setting_filter"));
    if (pcap_setfilter(packetCaptureHandle, &fcode) < 0)
    {
        pcap_close(packetCaptureHandle);
        pcap_freealldevs(devices);
        DIE(t("error_setting_filter") + ": " + std::string(pcap_geterr(packetCaptureHandle)));
    }

    IO::Warn(t("waiting_update_packets"));
    IO::Debug(t("starting_capture_loop"));

    pcap_freealldevs(devices); // 释放网卡列表资源
    pcap_loop(packetCaptureHandle, -1, packet_handler, NULL);
    
    IO::Info(t("captured_update_request") + ": " + result.productUrl);
    IO::Debug(t("closing_capture_handle"));
    pcap_close(packetCaptureHandle);
    global_pcap_handle = nullptr; // 清空全局句柄，避免野指针
}
