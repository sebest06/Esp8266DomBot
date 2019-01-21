#include "osapi.h"
#include "at_custom.h"
#include "user_interface.h"
#include "mem.h"
#include "espconn.h"


#define CFG_WRITE(x)	gpio_output_set(0,BIT(x),BIT(x),0)
#define CFG_READ(x)	gpio_output_set(0,0,0,BIT(x))

#define BIT_READ(x)   GPIO_INPUT_GET(x)
#define MAKE_HIGH(x)   GPIO_OUTPUT_SET(x,1)
#define MAKE_LOW(x)    GPIO_OUTPUT_SET(x,0)

#define PRIV_PARAM_START_SEC  0xc0
#define PRIV_PARAM_SAVE       0

#define PIR			12
#define RELEY		13
#define TEST		14

LOCAL os_timer_t scan_time_serv;

LOCAL char b_reset;

static struct espconn *at_espconn_demo_espconn_ptr = NULL;

// The IP address of the last system to send us any data.
LOCAL uint32_t last_addr = 0;

LOCAL uint32_t dummy = 0;

LOCAL char udpRun = 0;

static bool at_espconn_demo_flag = FALSE;

static uint32 at_espconn_demo_data_len = 0;

typedef struct
{
	unsigned char name[10];
	unsigned char ip[4];
}flasheado;

flasheado infoFlash;


// notify at module that espconn has received data
static void ICACHE_FLASH_ATTR
at_espconn_recv(void *arg, char *pusrdata, unsigned short len)
{
	uint8 buffer[64] = {0};
	//at_fake_uart_rx(pusrdata,len);
	os_sprintf(buffer, "RMT:%d,%s\r\n", len,pusrdata);
    	at_port_print(buffer);
	
	if (BIT_READ(RELEY))
	{
		MAKE_LOW(RELEY);
	}
	else
	{
		MAKE_HIGH(RELEY);
	}
}

static void ICACHE_FLASH_ATTR
at_espconn_send(void *arg)
{
	uint8 buffer[64] = {0};
	//at_fake_uart_rx(pusrdata,len);
	os_sprintf(buffer, "%s\r\n", "sent");
    	at_port_print(buffer);
}

void ICACHE_FLASH_ATTR
at_name_setup(uint8_t id, char *pPara)
{
    char *buff;
    uint8 buffer[32] = {0};

    pPara++;  //skip =
	
	at_data_str_copy(buffer,&pPara,9);
	buffer[9] = 0;

	os_memcpy(infoFlash.name,buffer,10);
    os_sprintf(buffer, "name = '%s'\r\n", infoFlash.name);
    at_port_print(buffer);

    
    spi_flash_erase_sector(PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE);
    spi_flash_write((PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE) * SPI_FLASH_SEC_SIZE,
        		(uint32 *)&infoFlash, sizeof(flasheado));
	
}

void ICACHE_FLASH_ATTR
at_server_setup(uint8_t id, char *pPara)
{
    char *buff;
    uint8 buffer[32] = {0};

    pPara++;  //skip =
    pPara++;  //skip "
    buff = strtok(pPara,".");
    infoFlash.ip[0] = atoi(buff);
    buff = strtok(NULL,".");
    infoFlash.ip[1] = atoi(buff);
    buff = strtok(NULL,".");
    infoFlash.ip[2] = atoi(buff);
    buff = strtok(NULL,",\"\r\n");
    infoFlash.ip[3] = atoi(buff);

	os_sprintf(buffer, "server = '%u.%u.%u.%u'\r\n", infoFlash.ip[0], infoFlash.ip[1], infoFlash.ip[2], infoFlash.ip[3]);
    at_port_print(buffer);
    
    spi_flash_erase_sector(PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE);
    spi_flash_write((PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE) * SPI_FLASH_SEC_SIZE,
        		(uint32 *)&infoFlash, sizeof(flasheado));
	
}

static void ICACHE_FLASH_ATTR
at_espconn_demo_discon_cb(void *arg)
{
  struct espconn *espconn_ptr = (struct espconn *)arg;

  os_printf("at demo espconn disconnected\r\n");
  at_espconn_demo_flag = FALSE;
  espconn_connect(espconn_ptr);
}

static void ICACHE_FLASH_ATTR
at_espconn_demo_connect_cb(void *arg)
{
	char buffer[64];
	unsigned int serial;
	os_printf("at demo espconn connected\r\n");
	espconn_set_opt((struct espconn*)arg,ESPCONN_COPY);
	at_espconn_demo_flag = TRUE;
	at_espconn_demo_data_len = 0;

	os_sprintf(buffer, "/hola %d\n",serial);
	espconn_send(at_espconn_demo_espconn_ptr,buffer,os_strlen(buffer));
}

static void ICACHE_FLASH_ATTR
at_espconn_demo_recon_cb(void *arg, sint8 errType)
{
	char buffer[64];
	unsigned int serial;

	struct espconn *espconn_ptr = (struct espconn *)arg;

	os_printf("at demo espconn reconnect\r\n");
	at_espconn_demo_flag = FALSE;
    espconn_connect(espconn_ptr);
	serial = system_get_chip_id();
	os_sprintf(buffer, "/hola %d\n",serial);
	espconn_send(at_espconn_demo_espconn_ptr,buffer,os_strlen(buffer));
}


void ICACHE_FLASH_ATTR
conectToServer()
{
  uint32 ip = 0;
  char buffer[64];
  at_espconn_demo_espconn_ptr = (struct espconn *)os_zalloc(sizeof(struct espconn));
  at_espconn_demo_espconn_ptr->type = ESPCONN_TCP;
  at_espconn_demo_espconn_ptr->state = ESPCONN_NONE;
  at_espconn_demo_espconn_ptr->proto.tcp = (esp_tcp *)os_zalloc(sizeof(esp_tcp));
  at_espconn_demo_espconn_ptr->proto.tcp->local_port = espconn_port();
  at_espconn_demo_espconn_ptr->proto.tcp->remote_port = 30666;

  os_sprintf(buffer, "%u.%u.%u.%u", infoFlash.ip[0], infoFlash.ip[1], infoFlash.ip[2], infoFlash.ip[3]);

  ip = ipaddr_addr(buffer);
  os_memcpy(at_espconn_demo_espconn_ptr->proto.tcp->remote_ip,&ip,sizeof(ip));
  espconn_regist_connectcb(at_espconn_demo_espconn_ptr, at_espconn_demo_connect_cb);
  espconn_regist_reconcb(at_espconn_demo_espconn_ptr, at_espconn_demo_recon_cb);
  espconn_regist_disconcb(at_espconn_demo_espconn_ptr, at_espconn_demo_discon_cb);
  espconn_regist_recvcb(at_espconn_demo_espconn_ptr, at_espconn_recv);
  espconn_regist_sentcb(at_espconn_demo_espconn_ptr, at_espconn_send);
  
  int salida = espconn_connect(at_espconn_demo_espconn_ptr);

	switch(salida)
	{
		case ESPCONN_RTE:
			os_sprintf(buffer, "ESPCONN_RTE\r\n");
		break;
		case ESPCONN_MEM:
			os_sprintf(buffer, "ESPCONN_MEM\r\n");
		break;
		case ESPCONN_ISCONN:
			os_sprintf(buffer, "ESPCONN_ISCONN\r\n");
		break;
		case ESPCONN_ARG:
			os_sprintf(buffer, "ESPCONN_ARG\r\n");
		break;
		default:
			os_sprintf(buffer, "OK\r\n");
		break;
	}
    at_port_print(buffer);

}

extern void at_exeCmdCiupdate(uint8_t id);
at_funcationType at_custom_cmd[] = {
    //{"+PARAM",6,NULL,NULL,at_param_setup,at_param_exe},
	{"+NAME",5,NULL,NULL,at_name_setup,NULL},
	{"+SERVER",7,NULL,NULL,at_server_setup,NULL},

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
}


void ICACHE_FLASH_ATTR
wifi_handle_event_cb(System_Event_t *evt)
{
     char buffer[64];
     os_sprintf(buffer,"event %x\n", evt->event);
     at_port_print(buffer);

     switch (evt->event) {
		case EVENT_STAMODE_DISCONNECTED:
		break;
         case EVENT_STAMODE_CONNECTED:
 	 break;
         case EVENT_STAMODE_GOT_IP:
			conectToServer();
			ETS_GPIO_INTR_ENABLE();
		break;
         case EVENT_SOFTAPMODE_STACONNECTED:
         break;

     }
}

// interrupt handler: this function will be executed on any edge of GPIO0
LOCAL void  gpio_intr_handler(void *dummy)
{
    int value;
    uint8 buffer[32] = {0};

    // clear gpio status. Say ESP8266EX SDK Programming Guide in  5.1.6. GPIO interrupt handler
    uint32 gpio_status = GPIO_REG_READ(GPIO_STATUS_ADDRESS);

	gpio_pin_intr_state_set(GPIO_ID_PIN(PIR), GPIO_PIN_INTR_DISABLE);

	os_delay_us(1000000);
    // if the interrupt was by GPIO14
    if (gpio_status & BIT(PIR))
    {
		if(at_espconn_demo_flag)
		{
			espconn_send(at_espconn_demo_espconn_ptr,"/sensor1\n",9);
			at_port_print("DISPARE!");
		}
    }

    GPIO_REG_WRITE(GPIO_STATUS_W1TC_ADDRESS, gpio_status & BIT(PIR));
    gpio_pin_intr_state_set(GPIO_ID_PIN(PIR), GPIO_PIN_INTR_POSEDGE);
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

    spi_flash_read((PRIV_PARAM_START_SEC + PRIV_PARAM_SAVE) * SPI_FLASH_SEC_SIZE,
        		(uint32 *)&infoFlash, sizeof(flasheado));

	at_init();
	gpio_init();
 	


    PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTDI_U, FUNC_GPIO12); //SELECCIONO GPIO14 en la funcion gpio
	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTMS_U, FUNC_GPIO14); //SELECCIONO GPIO14 en la funcion gpio


	PIN_FUNC_SELECT(PERIPHS_IO_MUX_MTCK_U, FUNC_GPIO3); //SELECCIONO GPIO13 en la funcion gpio

	
	PIN_PULLUP_DIS(PERIPHS_IO_MUX_GPIO2_U);
	PIN_PULLUP_DIS(PERIPHS_IO_MUX_MTDI_U);
	CFG_READ(PIR);
	
	CFG_WRITE(RELEY);
	MAKE_LOW(RELEY);

	CFG_WRITE(TEST);
	MAKE_LOW(TEST);

	// Disable interrupts by GPIO
    ETS_GPIO_INTR_DISABLE();

    // Attach interrupt handle to gpio interrupts.
    ETS_GPIO_INTR_ATTACH(gpio_intr_handler, &dummy);

    // clear gpio status. Say ESP8266EX SDK Programming Guide in  5.1.6. GPIO interrupt handler
    GPIO_REG_WRITE(GPIO_STATUS_W1TC_ADDRESS, BIT(PIR));

    // clear gpio status. Say ESP8266EX SDK Programming Guide in  5.1.6. GPIO interrupt handler
    gpio_pin_intr_state_set(GPIO_ID_PIN(PIR), GPIO_PIN_INTR_POSEDGE);

	


    
    os_sprintf(buf,"compile time:%s %s, RECONNECTION POLITY: %d",__DATE__,__TIME__,wifi_station_set_reconnect_policy(true));
    at_set_custom_info(buf);
    at_port_print("\r\nready\r\n");
    
    at_cmd_array_regist(&at_custom_cmd[0], sizeof(at_custom_cmd)/sizeof(at_custom_cmd[0]));

    wifi_set_event_handler_cb(wifi_handle_event_cb);
	

    os_sprintf(buf, "name = '%s'\r\n", infoFlash.name);
    at_port_print(buf);

	os_sprintf(buf, "server = '%u.%u.%u.%u'\r\n", infoFlash.ip[0], infoFlash.ip[1], infoFlash.ip[2], infoFlash.ip[3]);
    at_port_print(buf);

//os_timer_disarm(&scan_time_serv);
//os_timer_setfn(&scan_time_serv, (os_timer_func_t *)scan_time_callback, NULL);
//os_timer_arm(&scan_time_serv, 15000, 1);//15s


}



