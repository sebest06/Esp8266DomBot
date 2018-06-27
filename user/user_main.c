#include "osapi.h"
#include "at_custom.h"
#include "user_interface.h"
#include "mem.h"
#include "espconn.h"


#define PRIV_PARAM_START_SEC  0x3c
#define PRIV_PARAM_SAVE       0


LOCAL os_timer_t scan_time_serv;

LOCAL char b_reset;

/**Conexion TCP Administracion**/
// Structure holding the TCP connection information.
LOCAL struct espconn tcp_conn;

// TCP specific protocol structure.
LOCAL esp_tcp tcp_proto;

/***Conexion UDP Remoto***/
// Connection used to transmit UDP packets.
LOCAL struct espconn udp_tx;

// UDP specific procotol structure used for transmitting UDP packets.
LOCAL esp_udp udp_proto_tx;

/**Conexion UDP CELDA ***/
// Connection used to transmit UDP packets.
LOCAL struct espconn udp_tx_celda;

// UDP specific procotol structure used for transmitting UDP packets.
LOCAL esp_udp udp_proto_tx_celda;


// The IP address of the last system to send us any data.
LOCAL uint32_t last_addr = 0;

LOCAL uint32_t dummy = 0;

LOCAL char udpRun = 0;


typedef struct
{
	int pesoPromediado;				/**< guarda el peso ya promediado*/
	int vectorPesos[100];				/**< guarda las conversiones para promediar*/
	unsigned int priv_index_vector_promedios;	/**< indicie para el vector*/
    unsigned int recortes;
    unsigned int conversiones;
}balanza_adc;

typedef struct
{
     unsigned int recortes;
     unsigned int conversiones;
     unsigned char ip[4];
     unsigned char selfIp[4];
     unsigned int port;
     char configurado;
}flasheado;

volatile balanza_adc AdcDatos;
volatile flasheado balanzaFlash;

void checkIntegrityADCData()
{
    char buffer[64];
    if((AdcDatos.conversiones > 100)||(AdcDatos.conversiones < 1))
    {
        AdcDatos.conversiones = 10;
    }

	os_sprintf(buffer, "%d,%d\r\n", AdcDatos.recortes,AdcDatos.conversiones);
    	at_port_print(buffer);

}

// notify at module that espconn has received data
static void ICACHE_FLASH_ATTR
at_espconn_recv(void *arg, char *pusrdata, unsigned short len)
{
	uint8 buffer[64] = {0};
	//at_fake_uart_rx(pusrdata,len);
	os_sprintf(buffer, "RMT:%d,%s\r\n", len,pusrdata);
    	at_port_print(buffer);
}

static void ICACHE_FLASH_ATTR
at_espconn_send(void *arg)
{
	uint8 buffer[64] = {0};
	//at_fake_uart_rx(pusrdata,len);
	os_sprintf(buffer, "%s\r\n", "sent");
    	at_port_print(buffer);
}

static void ICACHE_FLASH_ATTR
at_espconn_recv_celda(void *arg, char *pusrdata, unsigned short len)
{
	uint8 buffer[64] = {0};
	//at_fake_uart_rx(pusrdata,len);
	os_sprintf(buffer, "CELDA:%s\r\n", pusrdata);
    	at_port_print(buffer);
}

static void ICACHE_FLASH_ATTR
at_espconn_send_celda(void *arg)
{
	uint8 buffer[64] = {0};
	//at_fake_uart_rx(pusrdata,len);
	//os_sprintf(buffer, "%s\r\n", "sent");
    	//at_port_print(buffer);
}

void ICACHE_FLASH_ATTR
at_exeStopCelda(uint8_t id)
{
    if(udpRun == 1)
    {
	    udpRun = 0;
	// Enable interrupts by GPIO
	    ETS_GPIO_INTR_DISABLE();

	    espconn_delete(&udp_tx_celda);
	    at_response_ok();
    }
}

void ICACHE_FLASH_ATTR
at_setupCelda(uint8_t id, char *pPara)
{

    char *buff;
    uint8 buffer[32] = {0};

    //os_sprintf(buffer, "%s\r\n", pPara);
    //at_port_print(buffer);

    pPara++;  //skip =
    pPara++;  //skip "
    buff = strtok(pPara,".");
    udp_proto_tx_celda.remote_ip[0] = atoi(buff);
    buff = strtok(NULL,".");
    udp_proto_tx_celda.remote_ip[1] = atoi(buff);
    buff = strtok(NULL,".");
    udp_proto_tx_celda.remote_ip[2] = atoi(buff);
    buff = strtok(NULL,",");
    udp_proto_tx_celda.remote_ip[3] = atoi(buff);
    buff = strtok(NULL,",\r\n");
    udp_proto_tx_celda.local_port = atoi(buff);
    udp_proto_tx_celda.remote_port = atoi(buff);

balanzaFlash.ip[0] = udp_proto_tx_celda.remote_ip[0];
balanzaFlash.ip[1] = udp_proto_tx_celda.remote_ip[1];
balanzaFlash.ip[2] = udp_proto_tx_celda.remote_ip[2];
balanzaFlash.ip[3] = udp_proto_tx_celda.remote_ip[3];
balanzaFlash.port = udp_proto_tx_celda.remote_port;
balanzaFlash.configurado = 1;

    spi_flash_erase_sector(PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE);
    spi_flash_write((PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE) * SPI_FLASH_SEC_SIZE,
        		(uint32 *)&balanzaFlash, sizeof(flasheado));

	if(udpRun == 1)
	{
		at_exeStopCelda(0);
	}

    // Prepare the UDP "connection" structure.
    udp_tx_celda.type = ESPCONN_UDP;
    udp_tx_celda.state = ESPCONN_NONE;
    udp_tx_celda.proto.udp = &udp_proto_tx_celda;
    espconn_regist_recvcb(&udp_tx_celda, at_espconn_recv_celda);
    espconn_regist_sentcb(&udp_tx_celda, at_espconn_send_celda);

    espconn_create(&udp_tx_celda);

    os_sprintf(buffer, "%d.%d.%d.%d:%d\r\n", udp_proto_tx_celda.remote_ip[0],udp_proto_tx_celda.remote_ip[1],udp_proto_tx_celda.remote_ip[2],udp_proto_tx_celda.remote_ip[3],udp_proto_tx_celda.remote_port);
    at_port_print(buffer);
    at_response_ok();
    udpRun = 1;
// Enable interrupts by GPIO
    ETS_GPIO_INTR_ENABLE();

}

void ICACHE_FLASH_ATTR
at_param_setup(uint8_t id, char *pPara)
{
    char *buff;
    uint8 buffer[32] = {0};

    //os_sprintf(buffer, "%s\r\n", pPara);
    //at_port_print(buffer);

    pPara++;  //skip =
    buff = strtok(pPara,",");
    AdcDatos.recortes = atoi(buff);
    buff = strtok(NULL,",");
    AdcDatos.conversiones = atoi(buff); 

    os_sprintf(buffer, "%d,%d\r\n", AdcDatos.recortes,AdcDatos.conversiones);
    at_port_print(buffer);

    checkIntegrityADCData();

    //flasheado salvar;
    balanzaFlash.recortes = AdcDatos.recortes;
    balanzaFlash.conversiones = AdcDatos.conversiones;   
    
    spi_flash_erase_sector(PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE);
    spi_flash_write((PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE) * SPI_FLASH_SEC_SIZE,
        		(uint32 *)&balanzaFlash, sizeof(flasheado));

}

static void ICACHE_FLASH_ATTR
admin_recv(void *arg, char *pusrdata, unsigned short len)
{
    uint8 buffer[64] = {0};
    uint8 mode;
    char *bssid;
    char *passw;
    char *buff;
    struct station_config stationConf;
    struct softap_config apConfig;
    //at_fake_uart_rx(pusrdata,len);
    os_sprintf(buffer, "ADM:%s\r\n", pusrdata);
    at_port_print(buffer);

    if(memcmp(pusrdata,"PARAM=",6)==0)
    {
        buff = pusrdata+5;
		espconn_send(arg, buff, strlen(buff));
        at_param_setup(0, buff);		
    }
    else if(memcmp(pusrdata,"MODO=",5)==0)
    {

       buff = strtok(pusrdata+5,",\r\n");
       if(buff != NULL)
       {
           mode = atoi(buff);
           bssid = strtok(NULL,",\r\n");
           if(bssid != NULL)
           {
                passw = strtok(NULL,",\r\n");
                if((mode < 3)&&(mode > 0))
                {
                    wifi_station_disconnect();
                    wifi_set_opmode(mode);
                    if(mode == 1) //station
                    {
						//wifi_set_opmode(mode); 
						wifi_station_get_config(&stationConf);
						stationConf.bssid_set = 0; //need not check MAC address of AP


						os_memcpy(&stationConf.ssid, bssid, os_strlen(bssid));
						stationConf.ssid[os_strlen(bssid)] = 0;
						os_memcpy(&stationConf.password, passw, os_strlen(passw));
						stationConf.password[os_strlen(passw)] = 0;
						//os_strcpy(&stationConf.password, passw); 

						os_sprintf(buffer, "%s,%s\r\n", stationConf.ssid,stationConf.password);
						//at_port_print(buffer);
						espconn_send(arg, buffer, strlen(buffer));

						wifi_station_set_config(&stationConf); 

						//wifi_station_disconnect();
						wifi_station_connect();
                    }
                    else
                    {                    
						os_sprintf(buffer, "%s->%s\r\n", bssid,passw);
						//at_port_print(buffer);
						espconn_send(arg, buffer, strlen(buffer));
						wifi_softap_get_config(&apConfig);

						char macaddr[6];

						wifi_get_macaddr(SOFTAP_IF, macaddr);
						apConfig.ssid_len = 0;

						os_memset(apConfig.ssid, 0, 32);
						os_memcpy(apConfig.ssid, bssid, 32);
						os_memset(apConfig.password, 0, sizeof(apConfig.password));
						os_memcpy(apConfig.password, passw, os_strlen(passw));
						apConfig.authmode = AUTH_WPA_WPA2_PSK;

						wifi_set_opmode(mode);
						wifi_softap_set_config(&apConfig);   			
						system_restart();
                    }
                    
                }
           }
       }
       
    }
    else if(memcmp(pusrdata,"CELDA=",6)==0)
    {
       buff = pusrdata+5;
	   espconn_send(arg, buff, strlen(buff));
       at_setupCelda(0,buff);
    }
	else if(memcmp(pusrdata,"SELF=",5)==0)
	{
		char selfIp[4];
		char *ptr;
		struct ip_info info;

		buff = pusrdata+5;
		buff++;  //skip "
	    ptr = strtok(buff,".\r\n");
		if(ptr == NULL) //DHCP
		{
			wifi_station_dhcpc_start();
		}
		else
		{	
			selfIp[0] = atoi(ptr);
		    ptr = strtok(NULL,".");
			if(ptr != NULL)
			{
		    	selfIp[1] = atoi(ptr);
		   		ptr = strtok(NULL,".\r\n");
				if(ptr != NULL)
				{
			    	selfIp[2] = atoi(ptr);
				    ptr = strtok(NULL,",\r\n");
					if(ptr != NULL)
					{
				    	selfIp[3] = atoi(ptr);
						espconn_send(arg, "OK\r\n", 4);
						//wifi_set_opmode(STATIONAP_MODE); //Set softAP + station mode
						//wifi_station_dhcpc_stop();

						//IP4_ADDR(&info.ip, selfIp[0], selfIp[1], selfIp[2], selfIp[3]);
						//IP4_ADDR(&info.gw, selfIp[0], selfIp[1], selfIp[2], 1);
						//IP4_ADDR(&info.netmask, 255, 255, 255, 0);
						//wifi_set_ip_info(STATION_IF, &info);

						balanzaFlash.selfIp[0] = selfIp[0];
						balanzaFlash.selfIp[1] = selfIp[1];
						balanzaFlash.selfIp[2] = selfIp[2];
						balanzaFlash.selfIp[3] = selfIp[3];
    					balanzaFlash.conversiones = AdcDatos.conversiones;   
    
    					spi_flash_erase_sector(PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE);
					    spi_flash_write((PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE) * SPI_FLASH_SEC_SIZE,
        				(uint32 *)&balanzaFlash, sizeof(flasheado));

					}
				}
			}
		}
	   
	}

}
static void ICACHE_FLASH_ATTR
admin_sent(void *arg)
{

}
static void ICACHE_FLASH_ATTR
server_connectcb(void *arg)
{
  struct espconn *conn=arg;
  espconn_regist_time(conn,0,0);
  espconn_regist_recvcb  (conn, admin_recv);
  //espconn_regist_reconcb (conn, httpconfig_recon_cb);
  //espconn_regist_disconcb(conn, httpconfig_discon_cb);
  espconn_regist_sentcb  (conn, admin_sent);
 
  char *transmission = "OK\r\n\r\nOK!\n";
  sint8 d = espconn_sent(conn,transmission,strlen(transmission));
}

void ICACHE_FLASH_ATTR
createServerAdm(void)
{

    char *buff;
	uint8 buffer[32] = {0};

    //os_sprintf(buffer, "%s\r\n", pPara);
    //at_port_print(buffer);

    tcp_proto.local_port = 5000;



    // Prepare the UDP "connection" structure.
    tcp_conn.type = ESPCONN_TCP;
    tcp_conn.state = ESPCONN_NONE;
    tcp_conn.proto.tcp = &tcp_proto;
    //espconn_regist_recvcb(&tcp_conn, admin_recv);
    //espconn_regist_sentcb(&tcp_conn, admin_send);

    //espconn_create(&tcp_conn);

    espconn_regist_connectcb(&tcp_conn, server_connectcb);
    espconn_accept(&tcp_conn);
	espconn_regist_time(&tcp_conn,0,0);


    at_response_ok();
}

void ICACHE_FLASH_ATTR
runCeldaAuto()
{
    char buffer[64];
    udp_proto_tx_celda.remote_ip[0] = balanzaFlash.ip[0];
    udp_proto_tx_celda.remote_ip[1] = balanzaFlash.ip[1];
    udp_proto_tx_celda.remote_ip[2] = balanzaFlash.ip[2];
    udp_proto_tx_celda.remote_ip[3] = balanzaFlash.ip[3];
    udp_proto_tx_celda.local_port = balanzaFlash.port;
    udp_proto_tx_celda.remote_port = balanzaFlash.port;

    // Prepare the UDP "connection" structure.
    udp_tx_celda.type = ESPCONN_UDP;
    udp_tx_celda.state = ESPCONN_NONE;
    udp_tx_celda.proto.udp = &udp_proto_tx_celda;
    //espconn_regist_recvcb(&udp_tx_celda, at_espconn_recv_celda);
    espconn_regist_sentcb(&udp_tx_celda, at_espconn_send_celda);

    espconn_create(&udp_tx_celda);

    os_sprintf(buffer, "%d.%d.%d.%d:%d\r\n", udp_proto_tx_celda.remote_ip[0],udp_proto_tx_celda.remote_ip[1],udp_proto_tx_celda.remote_ip[2],udp_proto_tx_celda.remote_ip[3],udp_proto_tx_celda.remote_port);
    at_port_print(buffer);
    at_response_ok();
    udpRun = 1;

}
char setAdcCuenta(int adc)
{
	volatile int auxAdc;
	char flagSort;
	int adcPromedio;
    unsigned int i;
	char salida = 0;
	adcPromedio = 0;

	if (adc > 0x40000)//40000)
	{
		adc = (0x80000-adc);
		adc *= -1;
		//adc = adc & 0x0007ffff;
	}

	AdcDatos.vectorPesos[AdcDatos.priv_index_vector_promedios] = adc;
	AdcDatos.priv_index_vector_promedios++;
	if(AdcDatos.priv_index_vector_promedios >= AdcDatos.conversiones)//balanzaRam.sizeConversiones)
	{
		AdcDatos.priv_index_vector_promedios = 0;
		// Sort
		flagSort = 1;
		while(flagSort)
		{
			flagSort = 0;
			
			for( i = 0; i < (AdcDatos.conversiones-1); i++)//balanzaRam.sizeConversiones-1); i++)
			{
				if(AdcDatos.vectorPesos[i] > AdcDatos.vectorPesos[i+1])
				{
					auxAdc = AdcDatos.vectorPesos[i];
					AdcDatos.vectorPesos[i] = AdcDatos.vectorPesos[i+1];
					AdcDatos.vectorPesos[i+1] = auxAdc;
					flagSort = 1;
				}
			}
		}
		int negative = 1;
		if(2*AdcDatos.recortes < AdcDatos.conversiones)//balanzaRam.sizeRecortes < balanzaRam.sizeConversiones)
		{
			for(i = AdcDatos.recortes; i < AdcDatos.conversiones-AdcDatos.recortes; i++)//balanzaRam.sizeRecortes; i < balanzaRam.sizeConversiones-balanzaRam.sizeRecortes; i++)
			{
				adcPromedio += AdcDatos.vectorPesos[i];
			}

			if(adcPromedio > 0x80000000)
			{
				adcPromedio*=-1;
				negative = -1;
			}

			adcPromedio /= (AdcDatos.conversiones-(2*AdcDatos.recortes));//(balanzaRam.sizeConversiones-(2*balanzaRam.sizeRecortes));
		}
		else
		{
			for(i = 0; i < AdcDatos.conversiones; i++)//balanzaRam.sizeConversiones; i++)
			{
				adcPromedio += AdcDatos.vectorPesos[i];
			}

			if(adcPromedio > 0x80000000)
			{
				adcPromedio*=-1;
				negative = -1;
			}

			adcPromedio /= AdcDatos.conversiones;//(balanzaRam.sizeConversiones);
		}

		adcPromedio *= negative;
		AdcDatos.pesoPromediado = adcPromedio;
		
        salida = 1;

	}
        return salida;
}
void ICACHE_FLASH_ATTR
at_setupCmdStart(uint8_t id, char *pPara)
{
    int adc = 0, err = 0, flag = 0,sensor;
    uint8 buffer[100] = {0};
	char salida;
    pPara++; // skip '='

    //get the first parameter
    // digit
    flag = at_get_next_int_dec(&pPara, &adc, &err);
    if (*pPara++ != ',') { // skip ','
        at_response_error();
        return;
    }
	flag = at_get_next_int_dec(&pPara, &sensor, &err);

    // flag must be ture because there are more parameter
	if(setAdcCuenta(adc))
	{
		os_sprintf(buffer,"ADC = %d,%d\r\n", AdcDatos.pesoPromediado,sensor);
		//at_port_print(buffer); //COMENTAME!
		espconn_send(&udp_tx_celda, buffer, strlen(buffer));
	}
}

// test :AT+TEST=1,"abc"<,3>
void ICACHE_FLASH_ATTR
at_setupCmdTest(uint8_t id, char *pPara)
{
    int dataLen = 0, err = 0, flag = 0;
    uint8 buffer[100] = {0};
char salida;
    pPara++; // skip '='

    //get the first parameter
    // digit
    flag = at_get_next_int_dec(&pPara, &dataLen, &err);

    // flag must be ture because there are more parameter
    if (flag == FALSE) {
        at_response_error();
        return;
    }

    if (*pPara++ != ',') { // skip ','
        at_response_error();
        return;
    }

    at_data_str_copy(buffer, &pPara, dataLen);
    buffer[dataLen] = '\r';

    if (*pPara != '\r') {
        at_response_error();
        return;
    }
	
    salida = espconn_send(&udp_tx, buffer, dataLen+1);

}

void ICACHE_FLASH_ATTR
at_testCmdTest(uint8_t id)
{
    uint8 buffer[32] = {0};

    os_sprintf(buffer, "%s\r\n", "at_testCmdTest");
    at_port_print(buffer);
    at_response_ok();
}

void ICACHE_FLASH_ATTR
at_queryCmdTest(uint8_t id)
{
    uint8 buffer[32] = {0};

    os_sprintf(buffer, "%s\r\n", "at_queryCmdTest");
    at_port_print(buffer);
    at_response_ok();
}

void ICACHE_FLASH_ATTR
at_exeCmdTest(uint8_t id)
{
    uint8 buffer[32] = {0};

    os_sprintf(buffer, "%s\r\n", "at_exeCmdTest");
    at_port_print(buffer);
    at_response_ok();
}

void ICACHE_FLASH_ATTR
at_param_exe(uint8_t id)
{
    uint8 buffer[32] = {0};

    os_sprintf(buffer, "%d,%d\r\n", AdcDatos.recortes,AdcDatos.conversiones);
    at_port_print(buffer);
}

extern void at_exeCmdCiupdate(uint8_t id);
at_funcationType at_custom_cmd[] = {
    //{"+RSEND", 6, at_testCmdTest, at_queryCmdTest, at_setupCmdTest, at_exeCmdTest},
    {"+ADC", 4, NULL, NULL, at_setupCmdStart, NULL},
    {"+CELDA", 6, NULL, NULL, at_setupCelda, NULL},
    {"+CELDASTOP",10,NULL,NULL,NULL,at_exeStopCelda},
    {"+PARAM",6,NULL,NULL,at_param_setup,at_param_exe},
#ifdef AT_UPGRADE_SUPPORT
    {"+CIUPDATE", 9,       NULL,            NULL,            NULL, at_exeCmdCiupdate}
#endif
};

/******************************************************************************
 * FunctionName : user_rf_cal_sector_set
 * Description  : SDK just reversed 4 sectors, used for rf init data and paramters.
 *                We add this function to force users to set rf cal sector, since
 *                we don't know which sector is free in user's application.
 *                sector map for last several sectors : ABBBCDDD
 *                A : rf cal
 *                B : at parameters
 *                C : rf init data
 *                D : sdk parameters
 * Parameters   : none
 * Returns      : rf cal sector
*******************************************************************************/
uint32 ICACHE_FLASH_ATTR
user_rf_cal_sector_set(void)
{
    enum flash_size_map size_map = system_get_flash_size_map();
    uint32 rf_cal_sec = 0;

    switch (size_map) {
        case FLASH_SIZE_4M_MAP_256_256:
            rf_cal_sec = 128 - 8;
            break;

        case FLASH_SIZE_8M_MAP_512_512:
            rf_cal_sec = 256 - 5;
            break;

        case FLASH_SIZE_16M_MAP_512_512:
        case FLASH_SIZE_16M_MAP_1024_1024:
            rf_cal_sec = 512 - 5;
            break;

        case FLASH_SIZE_32M_MAP_512_512:
        case FLASH_SIZE_32M_MAP_1024_1024:
            rf_cal_sec = 1024 - 5;
            break;

        default:
            rf_cal_sec = 0;
            break;
    }

    return rf_cal_sec;
}

void ICACHE_FLASH_ATTR
user_rf_pre_init(void)
{
}

LOCAL void ICACHE_FLASH_ATTR
scan_time_callback(void)
{
	struct station_config config;
	char buffer[64];
	if(b_reset)
	{
		system_restart();
	}
	//os_sprintf(buffer, "TIME-OUT!%d,%d\r\n", balanzaFlash.channel,station_connected);
	//at_port_print(buffer);
	
}


void ICACHE_FLASH_ATTR
wifi_handle_event_cb(System_Event_t *evt)
{
     char buffer[64];
     os_sprintf(buffer,"event %x\n", evt->event);
     at_port_print(buffer);

     switch (evt->event) {
		case EVENT_STAMODE_DISCONNECTED:
			if(!b_reset)
			{
				os_timer_arm(&scan_time_serv, 15000, 1);//15s
			}
			b_reset = TRUE;			
			//wifi_station_connect();
		break;
         case EVENT_STAMODE_CONNECTED:
			if(b_reset)
			{
				os_timer_disarm(&scan_time_serv);
			}
			b_reset = FALSE;
/*              os_sprintf(buffer, "connect to ssid %s, channel %d\n",
 	      evt->event_info.connected.ssid, 
 	      evt->event_info.connected.channel);
              at_port_print(buffer);
*/
 	 break;
         case EVENT_STAMODE_GOT_IP:
         case EVENT_SOFTAPMODE_STACONNECTED:
			  //at_exeStopCelda(1);
              runCeldaAuto();
         break;

     }
}

extern BOOL echoFlag;

void ICACHE_FLASH_ATTR
user_init(void)
{
	struct ip_info info;
    char buf[64] = {0};
    at_customLinkMax = 1;
	echoFlag = FALSE;

	b_reset = FALSE;

    AdcDatos.priv_index_vector_promedios = 0;

    //flasheado salvar;
    spi_flash_read((PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE) * SPI_FLASH_SEC_SIZE,
        		(uint32 *)&balanzaFlash, sizeof(flasheado));

    AdcDatos.recortes = balanzaFlash.recortes;
    AdcDatos.conversiones = balanzaFlash.conversiones;

    checkIntegrityADCData();

	at_init();

	wifi_station_dhcpc_stop();

	IP4_ADDR(&info.ip, balanzaFlash.selfIp[0], balanzaFlash.selfIp[1], balanzaFlash.selfIp[2], balanzaFlash.selfIp[3]);
	IP4_ADDR(&info.gw, balanzaFlash.selfIp[0], balanzaFlash.selfIp[1], balanzaFlash.selfIp[2], 1);
	IP4_ADDR(&info.netmask, 255, 255, 255, 0);
	wifi_set_ip_info(STATION_IF, &info);

    
    os_sprintf(buf,"compile time:%s %s",__DATE__,__TIME__);
    at_set_custom_info(buf);
    at_port_print("\r\nready\r\n");
    
    at_cmd_array_regist(&at_custom_cmd[0], sizeof(at_custom_cmd)/sizeof(at_custom_cmd[0]));

    createServerAdm();
    wifi_set_event_handler_cb(wifi_handle_event_cb);
	wifi_station_set_reconnect_policy(true);

    os_timer_disarm(&scan_time_serv);
	os_timer_setfn(&scan_time_serv, (os_timer_func_t *)scan_time_callback, NULL);
	//os_timer_arm(&scan_time_serv, 15000, 1);//15s

//    system_phy_set_max_tpw(1);

}



