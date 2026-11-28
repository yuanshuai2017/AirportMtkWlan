from pathlib import Path
import subprocess,sys,tempfile
b=Path(__file__).resolve().parent
src=Path(sys.argv[1]) if len(sys.argv)>1 else b.parents[1]/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp'
s=src.read_text();f=s[s.index('void\nmwx_mac_tx_free('):s.index('\nint\nmt7921_set_channel(')]
pre=r'''
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
struct mbuf {unsigned char* raw;size_t len,off;};
#define MTK_NATIVE_AWDL 1
#define AIRPORT_WCL 1
#define __IO80211_TARGET 260000
#define __MAC_26_0 260000
#include <HAL/MtkAwdlAnnouncement.hpp>
enum class MwxAwdlTx : uint8_t { None, Sync, Service, VerifiedService, Data, GroupData, BaAction, BaRequest };
struct mwx_txwi {int mt_busy; MwxAwdlTx mt_awdl; uint32_t mt_awdl_epoch; uint64_t mt_awdl_queue_time; bool mt_awdl_peer, mt_awdl_aggregate; mbuf *mt_mbuf;};
struct mwx_softc {
 int sc_txq;
 void *sc_awdl_controller;
 struct { unsigned num_streams; } sc_capa;
 struct { bool active; uint64_t lastDataAckUS; uint8_t mac[6]; } sc_awdl_peer;
 struct {int mt_count;mwx_txwi mt_data[16];} sc_txwi;
 MtkAwdl::AnnouncementCompletions sc_awdl_completions;
 uint32_t sc_awdl_channel_epoch;
};
void mwx_dma_tx_cleanup(mwx_softc*,int*){}
mbuf* m_pullup(mbuf*m,size_t){return m;}
size_t mbuf_len(mbuf*m){return m->len-m->off;}
size_t mbuf_pkthdr_len(mbuf*m){return m->len;}
void m_adj(mbuf*m,size_t n){assert(n<=mbuf_len(m));m->off+=n;}
void m_freem(mbuf*m){free(m->raw);delete m;}
#define mtod(m,t) ((t)((m)->raw+(m)->off))
#define le32toh(x) (x)
#define MT_TX_FREE_PAIR (1u<<31)
#define MT_TX_FREE_STATUS_MASK (3u<<13)
#define MT_TX_FREE0_MSDU_CNT_GET(x) (((x)>>16)&0x3ff)
#define MT_TX_FREE_MSDU_ID_GET(x) (((x)>>16)&0x7fff)
void mwx_tx_kick(mwx_softc*){}
uint64_t mwx_now_us(){return 1000;}
unsigned releases;
unsigned awdlWakes;
void mtkAwdlTxCompleted(void *) { ++awdlWakes; }
unsigned rate_acks = 0, rate_fails = 0;
void mwx_awdl_rate_feedback(mwx_softc*, bool failed, bool) { if (failed) ++rate_fails; else ++rate_acks; }
uint64_t mach_absolute_time() { return 2000000; }
void absolutetime_to_nanoseconds(uint64_t ticks, uint64_t *ns) { *ns = ticks; }
void mwx_txwi_put(mwx_softc*,mwx_txwi*mt){assert(mt->mt_busy);mt->mt_busy=0;if(mt->mt_mbuf){m_freem(mt->mt_mbuf);mt->mt_mbuf=nullptr;}releases++;}
mbuf* packet(size_t len){auto m=new mbuf{(unsigned char*)calloc(1,len),len,0};return m;}
'''
main=r'''
int main(int argc,char**argv){
 mwx_softc sc={};sc.sc_txwi.mt_count=16;
 if(argc>1){ // baseline reproducer: count excludes PAIR, so loop grows past the payload
  auto m=packet(12);auto p=mtod(m,uint32_t*);p[0]=1u<<16;p[2]=MT_TX_FREE_PAIR;mwx_mac_tx_free(&sc,m);return 0;
 }
 for(size_t len=0;len<8;len++)mwx_mac_tx_free(&sc,packet(len));
 for(unsigned pairs=0;pairs<64;pairs++){
  auto m=packet(8+4*(pairs+2));auto p=mtod(m,uint32_t*);p[0]=2u<<16;
  for(unsigned i=0;i<pairs;i++)p[2+i]=MT_TX_FREE_PAIR;
  p[2+pairs]=3u<<16;p[3+pairs]=4u<<16;
  sc.sc_txwi.mt_data[3].mt_busy=sc.sc_txwi.mt_data[4].mt_busy=1;unsigned prev=releases;
  mwx_mac_tx_free(&sc,m);assert(releases==prev+2);
 }
 for(unsigned n=1;n<64;n++){
  auto m=packet(8+4*n);auto p=mtod(m,uint32_t*);p[0]=1u<<16;
  for(unsigned i=0;i<n;i++)p[i+2]=MT_TX_FREE_PAIR;
  mwx_mac_tx_free(&sc,m);
 }
 auto m=packet(8+7*4);
 auto words=mtod(m,uint32_t*);
 words[0]=7u<<16;
 words[2]=(3u<<16);             // Service succeeded.
 words[3]=(4u<<16) | (2u<<13);  // Service failed.
 words[4]=(5u<<16);             // Sync succeeded.
 words[5]=(6u<<16) | (1u<<13);  // Ordinary traffic is excluded.
 words[6]=(3u<<16);             // Duplicate release is ignored.
 words[7]=(7u<<16);             // Unicast Data succeeded.
 words[8]=(8u<<16) | (1u<<13);  // Unicast Data failed.
 sc.sc_txwi.mt_data[3]={1,MwxAwdlTx::Service};
 sc.sc_txwi.mt_data[4]={1,MwxAwdlTx::Service};
 sc.sc_txwi.mt_data[5]={1,MwxAwdlTx::Sync};
 sc.sc_txwi.mt_data[6]={1,MwxAwdlTx::None};
 sc.sc_awdl_peer.active=true;
 const uint8_t peer[] = {2, 3, 4, 5, 6, 7};
 const uint8_t other[] = {4, 5, 6, 7, 8, 9};
 memcpy(sc.sc_awdl_peer.mac,peer,6);
 auto unicast=packet(24), failed=packet(24);
 memcpy(mtod(unicast,uint8_t*)+4,peer,6);
 memcpy(mtod(failed,uint8_t*)+4,other,6);
 sc.sc_txwi.mt_data[7]={1,MwxAwdlTx::Data,0,0,true,true,unicast};
 sc.sc_txwi.mt_data[8]={1,MwxAwdlTx::Data,0,0,true,true,failed};
 mwx_mac_tx_free(&sc,m);
 const auto &counts=sc.sc_awdl_completions;
 assert(awdlWakes==1 && sc.sc_awdl_peer.lastDataAckUS==1000);
 assert(counts.unicastAcks.lastActive(peer)==1000 && !counts.unicastAcks.lastActive(other));
 assert(counts.sent==2 && counts.failed==1);
 assert(counts.serviceSent==1 && counts.serviceFailed==1 && counts.lastStatus==1);
 assert(counts.dataSent==1 && counts.unicastReportedSent==1 && counts.dataFailed==1);
 assert(counts.unicastReportedFailed==1);
 assert(counts.peerAggTxSent==1 && counts.peerAggTxFailed==1 && counts.peerAggLastStatus==1);
 auto group=packet(8+2*4);
 auto groupEvents=mtod(group,uint32_t*);
 groupEvents[0]=2u<<16;
 groupEvents[2]=7u<<16;
 groupEvents[3]=(8u<<16) | (2u<<13);
 auto multicast=packet(24);
 mtod(multicast,uint8_t*)[4]=0x33;
 sc.sc_txwi.mt_data[7]={1,MwxAwdlTx::GroupData,0,0,false,false,multicast};
 sc.sc_txwi.mt_data[8]={1,MwxAwdlTx::GroupData};
 mwx_mac_tx_free(&sc,group);
 assert(counts.dataSent==2 && counts.dataFailed==2);
 assert(counts.peerAggTxSent==1 && counts.peerAggTxFailed==1 && counts.peerAggLastStatus==1);
 assert(awdlWakes==2);
 assert(counts.unicastReportedSent==1 && counts.unicastReportedFailed==1);
 assert(rate_acks==1 && rate_fails==1);
 auto baAction=packet(12);
 auto actionEvents=mtod(baAction,uint32_t*);
 actionEvents[0]=1u<<16;
 actionEvents[2]=(7u<<16) | (3u<<13);
 sc.sc_txwi.mt_data[7]={1,MwxAwdlTx::BaAction};
 const auto lastStatus=counts.lastStatus;
 const auto prevReleases=releases;
 mwx_mac_tx_free(&sc,baAction);
 assert(releases==prevReleases+1);
 assert(counts.lastStatus==lastStatus && counts.dataFailed==2 && counts.failed==1);
 assert(rate_acks==1 && rate_fails==1);
 assert(counts.peerBaReqAcked==0 && counts.peerBaReqFailed==0);
 auto requests=packet(8+3*4);
 auto reqEvents=mtod(requests,uint32_t*);
 reqEvents[0]=3u<<16;
 reqEvents[2]=7u<<16;
 reqEvents[3]=(8u<<16) | (2u<<13);
 reqEvents[4]=reqEvents[3];
 sc.sc_txwi.mt_data[7]={1,MwxAwdlTx::BaRequest};
 sc.sc_txwi.mt_data[8]={1,MwxAwdlTx::BaRequest};
 mwx_mac_tx_free(&sc,requests);
 assert(counts.peerBaReqAcked==1 && counts.peerBaReqFailed==1);
 assert(awdlWakes==2);
 assert(counts.lastStatus==lastStatus && counts.dataFailed==2 && counts.failed==1);
 assert(rate_acks==1 && rate_fails==1);
 auto switched=packet(8+2*4);
 auto events=mtod(switched,uint32_t*);
 events[0]=2u<<16;
 events[2]=3u<<16;
 events[3]=4u<<16;
 sc.sc_awdl_channel_epoch=10;
 sc.sc_txwi.mt_data[3]={1,MwxAwdlTx::VerifiedService,9};
 sc.sc_txwi.mt_data[4]={1,MwxAwdlTx::VerifiedService,10,1500000};
 mwx_mac_tx_free(&sc,switched);
 assert(counts.sent==4 && counts.serviceSent==3 && counts.verifiedServiceSent==1);
 assert(counts.verifiedCompletionLastUS==500 && counts.verifiedCompletionMaxUS==500);

 // A delayed ACK on the previous channel cannot sustain the current peer.
 auto ack = [](mwx_softc &device, const uint8_t *mac, uint32_t epoch) {
  auto tx = packet(24), completion = packet(12);
  memcpy(mtod(tx,uint8_t*)+4,mac,6);
  auto txFree=mtod(completion,uint32_t*);
  txFree[0]=1u<<16;
  txFree[2]=7u<<16;
  device.sc_txwi.mt_data[7]={1,MwxAwdlTx::Data,epoch,0,false,false,tx};
  mwx_mac_tx_free(&device,completion);
 };
 ack(sc,other,9);
 assert(!counts.unicastAcks.lastActive(other));
 ack(sc,other,10);
 assert(counts.unicastAcks.lastActive(other)==1000); // Also track fallback Data without a WCID.
 puts("PASS: AWDL completion attribution & rate feedback, short headers,64 valid mixed PAIR/MSDU events,63 truncated PAIR lists; extracted firmware TX-free parser ASan/UBSan.");
}
'''
tmp=tempfile.TemporaryDirectory(prefix='mtk-tx-test-');art=Path(tmp.name)
cpp=art/'free-test.cpp';exe=art/'free-test';cpp.write_text(pre+f+main)
subprocess.run(['clang++','-std=c++14','-fsanitize=address,undefined','-g','-I',str(b.parents[1]/'include'),str(cpp),'-o',str(exe)],check=True)
raise SystemExit(subprocess.run([str(exe)]+(['baseline'] if len(sys.argv)>2 else [])).returncode)
