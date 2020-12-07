/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

//先对是否是以太帧进行判断
struct ethernet_hdr* SimpleRouter::validateEther(const Buffer& packet, const std::string& inIface) const{
    //判断packet的大小
    if(packet.size()<sizeof(struct ethernet_hdr)){
        throw std::runtime_error("packet size too small");
    }
    auto* pEther=(struct ethernet_hdr*)packet.data();
    //判断ether_type是否为arp或ip
    uint16_t type = ethertype((uint8_t*)pEther);
    if(type!=ethertype_arp&&type!=ethertype_ip){
        throw std::runtime_error("Ethernet frame other than ARP and IPv4");
    }
    const Interface* iface = findIfaceByName(inIface);
    //判断dhost是否指向router
    if(!memcmp(pEther->ether_dhost,iface->addr.data(),6))
    {
        CERR("dhost is the router interface MAC address")
    }
    else{
        //广播地址
        if((pEther->ether_dhost[0]&pEther->ether_dhost[1]&pEther->ether_dhost[2]&pEther->ether_dhost[3]&pEther->ether_dhost[4]&pEther->ether_dhost[5])==0xff){
            CERR("dhost is boardcast address")
    }
        else{
            throw std::runtime_error("dhost is neither the router nor boardcast");
        }
    }
    return pEther;

}


//验证Arp
struct arp_hdr *SimpleRouter::validateArp(const Buffer &packet) const {
    //检验packet的大小
    if(packet.size()!=(sizeof(struct ethernet_hdr)+sizeof(struct arp_hdr))){
        throw std::runtime_error("the arp size is not correct");
    }
    auto* pArp = (struct arp_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
    //判断Arp是否是以太帧
    if(ntohs(pArp->arp_hrd)!=0x001){
        throw std::runtime_error("the arp hardware type is not ethernet");
    }
    //判断Arp的协议类型是否是IPv4
    if(ntohs(pArp->arp_pro)!=0x0800){
        throw std::runtime_error("the arp protocol type is not IPv4");
    }
    if(pArp->arp_hln!=0x06){
        throw std::runtime_error("the Arp HW addr len is not 0x06");
    }
    if(pArp->arp_pln!=0x04){
        throw std::runtime_error("the Arp Prot addr len is not 0x04");
    }
    if(ntohs(pArp->arp_op)!=1&&ntohs(pArp->arp_op)!=2){
        throw std::runtime_error("the Arp Opcode is neither Arp request nor Arp reply");
    }
    return pArp;

}

//发送Arp Reply
void SimpleRouter::sendArpReply(const Buffer &packet, const std::string &inIface) {
    auto* reply=new Buffer(packet);
    auto* pEther=(struct ethernet_hdr*)(packet.data());
    auto* pArp=(struct arp_hdr*)((u_int8_t*)pEther+sizeof(ethernet_hdr));
    auto* pReplyEther=(struct ethernet_hdr*)(reply->data());
    auto* pReplyArp=(struct arp_hdr*)((uint8_t*)pReplyEther+sizeof(ethernet_hdr));
    const Interface* iface = findIfaceByName(inIface);
    //在原Arp request的基础上需要修改的
    //ethernet source/destination
    memcpy(pReplyEther->ether_dhost,pEther->ether_shost,ETHER_ADDR_LEN);
    memcpy(pReplyEther->ether_shost,iface->addr.data(),ETHER_ADDR_LEN);
    //arp opcode
    pReplyArp->arp_op=htons(0x0002);
    //source/target MAC address and IP address
    pReplyArp->arp_sip=pArp->arp_tip;
    pReplyArp->arp_tip=pArp->arp_sip;
    memcpy(pReplyArp->arp_sha,iface->addr.data(),6);
    memcpy(pReplyArp->arp_tha,pArp->arp_sha,6);
    //无需修改entry

    //发送ARP reply packet
    sendPacket(*reply,inIface);
}

//处理接收到的Arp reply
void SimpleRouter::processArpReply(const Buffer &packet) {
    auto* pArp=(struct arp_hdr*)((uint8_t*)packet.data() + sizeof(struct ethernet_hdr));
    uint32_t ip=pArp->arp_sip;
    Buffer mac(pArp->arp_sha, pArp->arp_sha + 6);
    //如果是新的ip/MAC地址对
    if(m_arp.lookup(ip)== nullptr){
        CERR("insert new ip/MAC address pair")
        //插入Arp table并查找相关的arp requests
        auto arpRequest = m_arp.insertArpEntry(mac,ip);
        if(arpRequest== nullptr){
            CERR("no queued requests")
        }
        else{
            //处理目的地址为对应的ip/MAC地址对的包
            CERR("handle queued requests")
            for(const auto& PendingPacket: arpRequest->packets){
            handlePacket(PendingPacket.packet,PendingPacket.iface);
            }
            m_arp.removeRequest(arpRequest);
        }
    }
    else{
        CERR("ip/MAC address pair already in the arp table")
    }

}

//对Arp类型进行处理
void SimpleRouter::processArp(const Buffer &packet, const std::string &inIface)  {
    struct arp_hdr* pArp;
    //先检验Arp请求是否出错
    try{
        pArp=validateArp(packet);
    }
    catch (std::exception& e) {
        CERR(e.what())
        return;
    }
    catch (...) {
        CERR("unexpected error")
        return;
    }

    const Interface* iface = findIfaceByName(inIface);
    //对Arp request和Arp Reply进行分类处理
    //面对Arp request
    if(ntohs(pArp->arp_op)==1){
        if(pArp->arp_tip==iface->ip){
        CERR("send Arp reply")
        sendArpReply(packet,inIface);
        }
        else{
            CERR("the Arp reply destination is not the router,ignore")
        }
    }
    //面对Arp reply
    else if(ntohs(pArp->arp_op)==2){
        //面对Arp reply是无需判断destination的，而是应该充分利用信息，将不知道的ip/MAC对存到Arp cache中
        CERR("process Arp reply")
        processArpReply(packet);
    }

}

//检验是否为IPv4类型
struct ip_hdr *SimpleRouter::validateIPv4(const Buffer &packet) const {
    //先检验大小
    if(packet.size()<(sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr))){
        throw std::runtime_error("incorrect IPv4 packet size");
    }
    auto* pIPv4=(struct ip_hdr*)((u_int8_t*)packet.data()+sizeof(struct ethernet_hdr));
    //再检验checksum
    if(cksum(pIPv4,sizeof(struct ip_hdr))!=0xffff){
        throw std::runtime_error("incorrect checksum");
    }
    return pIPv4;
}

//检验ICMP类型是否出错
struct icmp_hdr *SimpleRouter::validateICMP(const Buffer &packet) {
    //先判断大小
    if(packet.size()<sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(struct icmp_hdr)){
        throw std::runtime_error("icmp packet size too small");
    }
    auto* pICMP = (struct icmp_hdr*)((uint8_t*)packet.data()+sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr));
    //检查ICMP类型是否是Echo request
    if(!(pICMP->icmp_type==8&&pICMP->icmp_code==0)){
        throw std::runtime_error("icmp type is not echo request");
    }
    if(cksum((uint8_t*)pICMP,packet.size()-sizeof(struct ethernet_hdr)-sizeof(struct ip_hdr))!=0xffff){
        throw std::runtime_error("icmp checksum is not correct");
    }
    return pICMP;
}

//处理ICMP
void SimpleRouter::processICMP(const Buffer &packet, const std::string &inIface) {
    auto* pIPv4=(struct ip_hdr*)((uint8_t*)packet.data()+sizeof(struct ethernet_hdr));
    auto* pEther=(struct ethernet_hdr*)((uint8_t*)packet.data());
        try{
        validateICMP(packet);
    }
    catch (std::exception& e) {
        CERR(e.what())
        return;
    }
    catch(...){
        CERR("unexpected error")
        return;
    }
    //查找路由表
    auto routingEntry = m_routingTable.lookup(pIPv4->ip_src);
    auto outIface=findIfaceByName(routingEntry.ifName);
    //查找ARP表
    auto arpEntry= m_arp.lookup(pIPv4->ip_src);
    //如果表中沒有对应的IP/MAC地址对，则先将request加入队列
    if(arpEntry == nullptr){
        CERR("Arp entry not found, queue ICMP echo reply")
        m_arp.queueRequest(pIPv4->ip_src, packet, inIface);
        return;
    }
    //如果有的话，发送Echo reply
    auto* reply=new Buffer(packet);
    auto* pReplyIcmp=(struct icmp_hdr*)((uint8_t*)reply->data()+sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr));
    auto* pReplyEther=(struct ethernet_hdr*)((uint8_t*)reply->data());
    auto* pReplyIp=(struct ip_hdr*)((uint8_t*)reply->data()+sizeof(struct ethernet_hdr));

    //修改ICMP header
    pReplyIcmp->icmp_type=0;
    pReplyIcmp->icmp_code=0;
    pReplyIcmp->icmp_sum=0;
    pReplyIcmp->icmp_sum=cksum((uint8_t*)pReplyIcmp, packet.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));

    //修改IP header
    pReplyIp->ip_id=0;
    pReplyIp->ip_src=pIPv4->ip_dst;
    pReplyIp->ip_dst=pIPv4->ip_src;
    pReplyIp->ip_ttl=64;
    pReplyIp->ip_sum=0;
    pReplyIp->ip_sum=cksum((uint8_t*)pReplyIp,sizeof(struct ip_hdr));

    //修改Ethernet header
    memcpy(pReplyEther->ether_shost,pEther->ether_dhost,6);
    memcpy(pReplyEther->ether_dhost,pEther->ether_shost,6);

    sendPacket(*reply,outIface->name);
}

//面对发向路由的udp/tcp请求，发送sendPortUnreachable message
void SimpleRouter::sendPortUnreachable(const Buffer &packet, const std::string &inIface) {
    auto pEther=(struct ethernet_hdr*)((uint8_t*)packet.data());
    auto pIPv4=(struct ip_hdr*)((uint8_t*)packet.data()+sizeof(struct ethernet_hdr));
    auto routingEntry = m_routingTable.lookup(pIPv4->ip_src);
    auto outIface=findIfaceByName(routingEntry.ifName);
    //查找ARP表
    auto arpEntry= m_arp.lookup(pIPv4->ip_src);
    //如果表中沒有对应的IP/MAC地址对，则先将request加入队列
    if(arpEntry == nullptr){
        CERR("Arp entry not found, queue ICMP port Unreachable message")
        m_arp.queueRequest(pIPv4->ip_src, packet, inIface);
        return;
    }
    //如果有的话，发送Echo reply
    auto* reply=new Buffer(sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(icmp_t3_hdr));
    auto* pReplyIcmpT3=(struct icmp_t3_hdr*)((uint8_t*)reply->data()+sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr));
    auto* pReplyEther=(struct ethernet_hdr*)((uint8_t*)reply->data());
    auto* pReplyIpv4=(struct ip_hdr*)((uint8_t*)reply->data()+sizeof(struct ethernet_hdr));
    memcpy(pReplyEther, pEther, sizeof(struct ethernet_hdr));
    memcpy(pReplyIpv4, pIPv4, sizeof(struct ip_hdr));

        //处理ICMPT3
        pReplyIcmpT3->icmp_type=3;
        pReplyIcmpT3->icmp_code=3;
        pReplyIcmpT3->next_mtu=0;
        pReplyIcmpT3->unused=0;
        pReplyIcmpT3->icmp_sum=0;
        memcpy((uint8_t*)(pReplyIcmpT3->data), (uint8_t*)pIPv4, ICMP_DATA_SIZE);
        pReplyIcmpT3->icmp_sum=cksum(pReplyIcmpT3,sizeof(struct icmp_t3_hdr));

        //处理IP
        pReplyIpv4->ip_id=0;
//        pReplyIpv4->ip_src=pIPv4->ip_dst;
        pReplyIpv4->ip_src=outIface->ip;
        pReplyIpv4->ip_dst=pIPv4->ip_src;
        pReplyIpv4->ip_ttl=64;
        pReplyIpv4->ip_p=ip_protocol_icmp;
        pReplyIpv4->ip_len=htons(sizeof(struct ip_hdr)+sizeof(struct icmp_t3_hdr));
        pReplyIpv4->ip_sum=0;
        pReplyIpv4->ip_sum=cksum(pReplyIpv4,sizeof(struct ip_hdr));

    //处理Ethernet
    memcpy(pReplyEther->ether_shost, outIface->addr.data(), 6);
    memcpy(pReplyEther->ether_dhost, arpEntry->mac.data(), 6);

    sendPacket(*reply, outIface->name);
}

//发送Time Exceeded Message
void SimpleRouter::sendTimeExceeded(const Buffer &packet, const std::string &inIface) {
    auto pEther=(struct ethernet_hdr*)((uint8_t*)packet.data());
    auto pIPv4=(struct ip_hdr*)((uint8_t*)packet.data()+sizeof(struct ethernet_hdr));
    auto routingEntry = m_routingTable.lookup(pIPv4->ip_src);
    auto outIface=findIfaceByName(routingEntry.ifName);
    //查找ARP表
    auto arpEntry= m_arp.lookup(pIPv4->ip_src);
    //如果表中沒有对应的IP/MAC地址对，则先将request加入队列
    if(arpEntry == nullptr){
        CERR("Arp entry not found, queue ICMP Time Exceeded message")
        m_arp.queueRequest(pIPv4->ip_src, packet, inIface);
        return;
    }
    //如果有的话，发送Echo reply
    auto* reply=new Buffer(sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(icmp_t3_hdr));
    auto* pReplyIcmpT3=(struct icmp_t3_hdr*)((uint8_t*)reply->data()+sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr));
    auto* pReplyEther=(struct ethernet_hdr*)((uint8_t*)reply->data());
    auto* pReplyIpv4=(struct ip_hdr*)((uint8_t*)reply->data()+sizeof(struct ethernet_hdr));
    memcpy(pReplyEther, pEther, sizeof(struct ethernet_hdr));
    memcpy(pReplyIpv4, pIPv4, sizeof(struct ip_hdr));

    //处理ICMPT3
    pReplyIcmpT3->icmp_type=11;
    pReplyIcmpT3->icmp_code=0;
    pReplyIcmpT3->next_mtu=0;
    pReplyIcmpT3->unused=0;
    pReplyIcmpT3->icmp_sum=0;
    memcpy((uint8_t*)(pReplyIcmpT3->data), (uint8_t*)pIPv4, ICMP_DATA_SIZE);
    pReplyIcmpT3->icmp_sum=cksum(pReplyIcmpT3,sizeof(struct icmp_t3_hdr));

    //处理IP
    pReplyIpv4->ip_id=0;
    pReplyIpv4->ip_src=outIface->ip;
    pReplyIpv4->ip_dst=pIPv4->ip_src;
    pReplyIpv4->ip_ttl=64;
    pReplyIpv4->ip_p=ip_protocol_icmp;
    pReplyIpv4->ip_len=htons(sizeof(struct ip_hdr)+sizeof(struct icmp_t3_hdr));
    pReplyIpv4->ip_sum=0;
    pReplyIpv4->ip_sum=cksum(pReplyIpv4,sizeof(struct ip_hdr));

    //处理Ethernet
    memcpy(pReplyEther->ether_shost, outIface->addr.data(), 6);
    memcpy(pReplyEther->ether_dhost, arpEntry->mac.data(), 6);

    sendPacket(*reply, outIface->name);

}

//转发IPv4数据报
void SimpleRouter::forwardIPv4(const Buffer &packet, const std::string &inIface) {
   // auto pEther=(struct ethernet_hdr*)((uint8_t*)packet.data());
    auto pIPv4=(struct ip_hdr*)((uint8_t*)packet.data()+sizeof(struct ethernet_hdr));
    auto routingEntry = m_routingTable.lookup(pIPv4->ip_dst);
    auto outIface=findIfaceByName(routingEntry.ifName);
    //查找ARP表
    auto arpEntry= m_arp.lookup(pIPv4->ip_dst);

    auto* forward=new Buffer (packet);
    auto* pForwardEther=(struct ethernet_hdr*)((uint8_t*)forward->data());
    auto* pForwardIpv4=(struct ip_hdr*)((uint8_t*)forward->data()+sizeof(struct ethernet_hdr));

    //设置IP
    pForwardIpv4->ip_ttl--;
    pForwardIpv4->ip_sum=0;
    pForwardIpv4->ip_sum=cksum(pForwardIpv4,sizeof(struct ip_hdr));

    //设置Ethernet
    memcpy(pForwardEther->ether_shost, outIface->addr.data(), 6);
    memcpy(pForwardEther->ether_dhost, arpEntry->mac.data(), 6);
    //发送数据报
    sendPacket(*forward, routingEntry.ifName);
}

//处理IPv4数据报
void SimpleRouter::processIPv4(const Buffer &packet, const std::string &inIface) {
    struct ip_hdr* pIPv4;
    //先检验IPv4类型
    try{
        pIPv4=validateIPv4(packet);
    }
    catch (std::exception& e) {
        CERR(e.what())
        return;
    }
    catch (...) {
        CERR("unexpected Error")
        return;
    }
    uint32_t ip = pIPv4->ip_dst;
    uint8_t protocol=pIPv4->ip_p;
    //如果指向路由器
    if(findIfaceByIp(ip)!= nullptr){
        CERR("ip packet destined to router")
        //如果是ICMP
        if(protocol==ip_protocol_icmp){
            CERR("process ICMP")
            processICMP(packet,inIface);
        }
        //如果是TCP或UDP
        else if(protocol==ip_protocol_tcp||protocol==ip_protocol_udp){
            CERR("send Port unreachable")
            sendPortUnreachable(packet,inIface);
        }
    }
    //如果指向其他地址
    else{
        CERR("datagrams to be forwarded")
        if(pIPv4->ip_ttl-1==0){
            CERR("send Time Exceeded message")
            sendTimeExceeded(packet,inIface);
        }
        else{
            //查找路由表
            auto routingEntry = m_routingTable.lookup(pIPv4->ip_dst);
           // auto outIface=findIfaceByName(routingEntry.ifName);
            //查找ARP表
            auto arpEntry= m_arp.lookup(pIPv4->ip_dst);
            //如果表中沒有对应的IP/MAC地址对，则先将request加入队列
            if(arpEntry == nullptr){
                CERR("Arp entry not found, queue Arp request")
                m_arp.queueRequest(pIPv4->ip_dst, packet, inIface);
                return;
            }
            else{
                CERR("forward IPv4 packet")
                forwardIPv4(packet,inIface);
            }
        }
    }

}

//发送Host Unreachable Message
void SimpleRouter::sendHostUnreachable(const Buffer &packet) {
    auto pEther=(struct ethernet_hdr*)((uint8_t*)packet.data());
    auto pIPv4=(struct ip_hdr*)((uint8_t*)packet.data()+sizeof(struct ethernet_hdr));
    auto routingEntry = m_routingTable.lookup(pIPv4->ip_src);
    auto outIface=findIfaceByName(routingEntry.ifName);
    //查找ARP表
    auto arpEntry= m_arp.lookup(pIPv4->ip_src);

    auto* reply=new Buffer(sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)+sizeof(icmp_t3_hdr));
    auto* pReplyIcmpT3=(struct icmp_t3_hdr*)((uint8_t*)reply->data()+sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr));
    auto* pReplyEther=(struct ethernet_hdr*)((uint8_t*)reply->data());
    auto* pReplyIpv4=(struct ip_hdr*)((uint8_t*)reply->data()+sizeof(struct ethernet_hdr));
    memcpy(pReplyEther, pEther, sizeof(struct ethernet_hdr));
    memcpy(pReplyIpv4, pIPv4, sizeof(struct ip_hdr));

    //处理ICMPT3
    pReplyIcmpT3->icmp_type=3;
    pReplyIcmpT3->icmp_code=1;
    pReplyIcmpT3->next_mtu=0;
    pReplyIcmpT3->unused=0;
    pReplyIcmpT3->icmp_sum=0;
    memcpy((uint8_t*)(pReplyIcmpT3->data), (uint8_t*)pIPv4, ICMP_DATA_SIZE);
    pReplyIcmpT3->icmp_sum=cksum(pReplyIcmpT3,sizeof(struct icmp_t3_hdr));

    //处理IP
    pReplyIpv4->ip_id=0;
    pReplyIpv4->ip_src=pIPv4->ip_dst;
    pReplyIpv4->ip_dst=pIPv4->ip_src;
    pReplyIpv4->ip_ttl=64;
    pReplyIpv4->ip_p=ip_protocol_icmp;
    pReplyIpv4->ip_len=htons(sizeof(struct ip_hdr)+sizeof(struct icmp_t3_hdr));
    pReplyIpv4->ip_sum=0;
    pReplyIpv4->ip_sum=cksum(pReplyIpv4,sizeof(struct ip_hdr));

    //处理Ethernet
    memcpy(pReplyEther->ether_shost, outIface->addr.data(), 6);
    memcpy(pReplyEther->ether_dhost, arpEntry->mac.data(), 6);

    sendPacket(*reply, outIface->name);
}

//发送Arp request
void SimpleRouter::sendArpRequest(uint32_t ip) {
    Buffer &request = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)));
    auto *pEther = (struct ethernet_hdr*)(request.data());
    auto *pArp = (struct arp_hdr*)((uint8_t*)pEther + sizeof(struct ethernet_hdr));
    const auto routing_entry = m_routingTable.lookup(ip);
    const auto outIface = findIfaceByName(routing_entry.ifName);

    //设置Arp
    pArp->arp_hrd=htons(0x0001);
    pArp->arp_pro=htons(0x0800);
    pArp->arp_hln=0x06;
    pArp->arp_pln=0x04;
    pArp->arp_op=htons(0x01);
    pArp->arp_sip=outIface->ip;
    pArp->arp_tip=ip;
    memcpy(pArp->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
    //在ArpRequest中Destination hardware address 取000000
    for (unsigned char & i : pArp->arp_tha)
    {
        i = 0xff;
    }
    //设置Ethernet
    memcpy(pEther->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
    for (unsigned char & i : pEther->ether_dhost)
    {
        i = 0xff;
    }
    pEther->ether_type = htons(0x0806);
    sendPacket(request, outIface->name);
}

void SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
    std::lock_guard<std::recursive_mutex> lock(m_arp.m_mutex);
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }
  struct ethernet_hdr* pEther;
  //先对以太帧进行判断 不是返回错误
  try{
      pEther=validateEther(packet,inIface);
  }
  catch (std::exception& e) {
    CERR(e.what())
    return;
  }
  catch (...) {
    CERR("unexpected Error")
    return;
  }
  //对类型进行判断
  //如果是Arp类型
  if(ntohs(pEther->ether_type)==ethertype_arp){
      CERR("process Arp packet")
    processArp(packet,inIface);
  }
  else if(ntohs(pEther->ether_type)==ethertype_ip){
    CERR("process IPv4 packet")
    processIPv4(packet,inIface);
  }
  else{
      CERR("packet is neither Arp nor IPv4")
  }

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}




} // namespace simple_router {
