
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <pcap.h>
#include <arpa/inet.h>

#define PRC_SUCCEEDED                   0
#define PRC_FAILED                      1

#define ETH_INTERFACE_MAX_COUNT         10
#define ETH_INT_NAME_MAX_LEN            20

#define SIZE_OF_ETH_TX_BUF              150

pcap_t *pcapIntHandle;
uint8_t txBuf[SIZE_OF_ETH_TX_BUF];


typedef struct __attribute__((packed)){
    char ethName[ETH_INT_NAME_MAX_LEN];
} ETH_NAME_LIST_T;

void getPacketInfo(const uint8_t *packet, struct pcap_pkthdr packHeader) 
{
    printf("Length of capture: %d\n", packHeader.caplen);
    printf("Length of packet %d\n", packHeader.len);
}

//pcap receive data available callback
void pcapRDA(uint8_t *args, const struct pcap_pkthdr *packHeader, const uint8_t *packBody)
{
    getPacketInfo(packBody, *packHeader);
    if(!pcap_sendpacket(pcapIntHandle, txBuf, SIZE_OF_ETH_TX_BUF))
        printf("txBuf is sent successfully!\r\n");
    else
        printf("txBuf is NOT sent!\r\n");
}

int eth_Get_List_Devices(ETH_NAME_LIST_T *ethIntNameList)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *pcapInterfaceList;
    pcap_t *pcapInt;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    if(PCAP_ERROR == pcap_findalldevs(&pcapInterfaceList, errbuf)){
        printf("PCAP can not detect any interface!\r\n Error:\r\n%s", errbuf);
        pcap_freealldevs(pcapInterfaceList);
        return PRC_FAILED;
    }
    
    printf("\r\n");
    for(; pcapInterfaceList; pcapInterfaceList = pcapInterfaceList->next){
        //open device just to check the data link type / interface
        pcapInt = pcap_open_live(pcapInterfaceList->name , BUFSIZ, 1, -1, errbuf);
        if(NULL == pcapInt){
            //printf("\r\nError for interface:%s, pcap_open_live(): %s\n", pcapInterfaceList->name , errbuf); 
            continue;
        }else{
            int dataLink = pcap_datalink(pcapInt);  //get data link info.
            if(DLT_EN10MB == dataLink){ //if it is Ethernet,
                static int index = 0;
                memmove(ethIntNameList[index].ethName, pcapInterfaceList->name, strlen(pcapInterfaceList->name));
                index++;
                if(index >= ETH_INTERFACE_MAX_COUNT)
                    break;
            }
            pcap_close(pcapInt);
        }
    }
    pcap_freealldevs(pcapInterfaceList);
    return PRC_SUCCEEDED;
}


int main(void)
{
    char pcapErrbuf[PCAP_ERRBUF_SIZE];
    ETH_NAME_LIST_T ethInterfaceNameList[ETH_INTERFACE_MAX_COUNT];
    struct in_addr netAddr, subnetMask;   //can handle both ip and subnet mask.
    //init txbuf
    txBuf[0] = 0x01;
    txBuf[1] = 0x01;
    txBuf[2] = 0x01;
    txBuf[3] = 0x01;
    txBuf[4] = 0x01;
    txBuf[5] = 0x01;
    txBuf[6] = '-';
    txBuf[7] = 'H';
    txBuf[8] = 'N';
    txBuf[9] = 'K';
    txBuf[10] = 'R';
    txBuf[11] = '-';
    for(int i = 12; i < SIZE_OF_ETH_TX_BUF; i++)
        txBuf[i] = i;


    //version
    const char *pcapVersion = pcap_lib_version();
    printf("PCAP Library Version:%s\r\n", pcapVersion);
    for(int i = 0;i < ETH_INTERFACE_MAX_COUNT; i++)
        memset(ethInterfaceNameList[i].ethName, 0, ETH_INT_NAME_MAX_LEN);
    //get all devices whose data link type is ethernet.
    eth_Get_List_Devices(ethInterfaceNameList);
    printf("\r\nEthernet Interface List:\r\n");
    for(int i = 0; i < ETH_INTERFACE_MAX_COUNT; i++){
        if(*ethInterfaceNameList[i].ethName == '\0')   break;
        printf("%d) \r\nName:%s\r\n", i + 1, ethInterfaceNameList[i].ethName);
         /* Get device info */
        int lookup_return_code = pcap_lookupnet(ethInterfaceNameList[i].ethName, &(netAddr.s_addr), &(subnetMask.s_addr), pcapErrbuf);
        if(PCAP_ERROR != lookup_return_code){
            printf("Network Addr (not IP):%s\r\n", inet_ntoa(netAddr));
            printf("Subnet Mask:%s\r\n", inet_ntoa(subnetMask));
        }else
        {
            printf("IP & Subnet Error: %s\r\n",pcapErrbuf);
        }
    }
    //Get default device to capture
    char *dev = pcap_lookupdev(pcapErrbuf);
    printf("\r\nDefault interface:%s\r\n", dev);
    pcapIntHandle = pcap_open_live(dev , BUFSIZ, 1, -1, pcapErrbuf);
    if(NULL != pcapIntHandle){
        printf("\r\nStarting to capture the packets incoming to default interface...\r\n");
        pcap_loop(pcapIntHandle, 0, pcapRDA, NULL);   //get in infinite-loop and call your own callback when each packet is received.
    }
    return EXIT_SUCCESS;
}


