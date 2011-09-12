/**
  * Syringe-base irecovery -- irecovery.c
  * Copyright (C) 2010 Chronic-Dev Team
  * Copyright (C) 2010 Joshua Hill
  * Copyright (C) 2010 iH8sn0w
  *
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "libirecovery.h"
#include "libpois0n.h"


void print_progress(double progress) {
	
	int i = 0;	
	if(progress < 0) return;
	if(progress > 100) progress = 100;

	printf("\r[");
	for(i = 0; i < 50; i++) {
		if(i < progress / 2)
			printf("=");
		else
			printf(" ");
	}
	printf("] %3.1f%%", progress);
	if(progress == 100)
		printf("\n");
}

int progress_cb(irecv_client_t client, const irecv_event_t* event) {
	if (event->type == IRECV_PROGRESS)
		print_progress(event->progress);
	return 0;
}


void print_usage(const char *argv0) {
	printf("\niRecovery - Recovery Utility\nOriginally made by westbaer\nThanks to pod2g, tom3q, planetbeing, geohot, and posixninja.\n");
	printf("\nThis is based off syringe available at: http://github.com/posixninja/syringe");
	printf("\nAnd iH8sn0w's syringe-irecovery: http://github.com/iH8sn0w/syringe-irecovery");
	printf("\n\nModified by Neal (iNeal). Use it at your own risk.\n\n");
	printf("Usage: ./%s [args]\n\n", argv0);
	printf("\t-c <command>\tsend a single command.\n");
	printf("\t-f <file>\tupload a file (to 0x21,1).\n");
	printf("\t-i\t\tGet device info. (ECID, BDID, etc.)\n");
	printf("\t-r\t\tReset the USB counters.\n");
	printf("\t-detect\t\tGet device id. (n90ap)\n");
	printf("\t-find\t\tFind device in recovery or DFU mode.\n");
	printf("\t-kick\t\tKick the device out of Recovery Mode.\n");
	printf("\t================ Exploits ================\n");
	printf("\t-e\t\tsend limera1n or steaks4uce [bootrom exploits].\n");
	printf("\t-k <payload>\tsend the 0x21,2 usb exploit. [ < 3.1.2 iBoot exploit].\n");
	printf("\t==========================================\n");
	return;
}


int main(int argc, char* argv[]) {

	if(argc < 2)
		print_usage(argv[0]);
	else {
		char** pArg;
		for (pArg = argv + 1; pArg < argv + argc; ++pArg) {
			const char* arg = *pArg;
			int* pIntOpt = NULL;
			
			if (!strcmp(arg, "-h") || !strcmp(arg, "-help"))
			{
				print_usage(argv[0]);
			}
			else if (!strcmp(arg, "-e"))
			{
				int can_ra1n = 0;
				unsigned int cpid;
				irecv_error_t error;
				irecv_init();

				printf("\n");

				error = irecv_open_attempts(&client, 10);
				if (error != IRECV_E_SUCCESS) return -error;

				if (irecv_get_cpid(client, &cpid) == IRECV_E_SUCCESS)
				{
					if((cpid > 8900) || (cpid = 8720))	can_ra1n = 1;
				}
				if (client->mode == kDfuMode && can_ra1n)
				{
					int ret;
					irecv_close(client);
					irecv_exit();

					pois0n_init();

					ret = pois0n_is_ready();
					if (ret < 0)	return ret;

					ret = pois0n_is_compatible();
					if (ret < 0)	return ret;

					pois0n_injectonly();

					irecv_close(client);
					client = NULL;
				}
				else
				{
					if(client->mode == kDfuMode) printf("[!] Device not compatible with limera1n or steaks4uce. [!]\n");
					if(client->mode != kDfuMode) printf("[!] No device found in DFU Mode. [!]\n");
				}
			}
			else if (!strcmp(arg, "-k"))
			{
				if (argc >= 3) {
					int ret;
					irecv_open_attempts(&client, 10);
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					printf("\n[!] Sending USB exploit... [!]\n");
					ret = irecv_send_file(client, argv[2],0);
					if (ret == IRECV_E_SUCCESS) {
						irecv_send_exploit(client);
						printf("\n[!] USB exploit sent! [!]\n");
					} else {
						printf("\n[!] Failed to send the Exploit. Error: %d [!]\n", ret);
					}
				} else {
					printf("\n[!] No payload was specified! [!]\n");
				}
			}
			else if (!strcmp(arg, "-c"))
			{
				if (argc >= 3) {
					int ret;
					irecv_open_attempts(&client, 10);
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					ret = irecv_send_command(client, argv[2]);
					if (ret == IRECV_E_SUCCESS)
						printf("\nCommand Sent!\n");
					else
						printf("\nFailed to send command.\n");
					irecv_exit();
				} else {
					printf("\nNo command was specified.\n");
				}
			}
			else if (!strcmp(arg, "-f"))
			{
				if (argc >= 3) {
					int ret;
					irecv_open_attempts(&client, 10);
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					if (client->mode == kDfuMode) {
						printf("\nUploading file in DFU...\n\n");
						ret = irecv_send_file(client, argv[2], 1);
						if (ret == IRECV_E_SUCCESS)
							printf("\nFile Sent!\n");
						else
							printf("\nFailed to send the file.\n");
					}
					else if (client->mode == kRecoveryMode1 || client->mode == kRecoveryMode2 || client->mode == kRecoveryMode3 || client->mode == kRecoveryMode4)
					{
						printf("\nUploading file in Recovery Mode...\n\n");
						ret = irecv_send_file(client, argv[2],0);
						if (ret == IRECV_E_SUCCESS)
							printf("\nFile Sent!\n");
						else
							printf("\nFailed to send the file.\n");
					} else {
							printf("\nNo device found in Recovery or DFU Mode.\n");
					}
					irecv_exit();
				} else {
					printf("\nNo file was specified.\n");
				}
			}
			else if (!strcmp(arg, "-i"))
			{
				int ret;
				unsigned int cpid, bdid;
				unsigned long long ecid;
				unsigned char srnm[13], imei[16], bt[16];
				printf("\n");
				irecv_open_attempts(&client, 10);

				ret = irecv_get_cpid(client, &cpid);
				if (ret == IRECV_E_SUCCESS) printf("CPID: %d\n", cpid);
				else printf("Failed to get CPID.\n");

				ret = irecv_get_bdid(client, &bdid);
				if (ret == IRECV_E_SUCCESS) printf("BDID: %d\n", bdid);
				else printf("Failed to get BDID.\n");

				ret = irecv_get_ecid(client, &ecid);
				if (ret == IRECV_E_SUCCESS) printf("ECID: %lld\n", ecid);
				else printf("Failed to get ECID.\n");

				ret = irecv_get_srnm(client, srnm);
				if (ret == IRECV_E_SUCCESS) printf("SRNM: %s\n", srnm);
				else printf("Failed to get SRNM.\n");

				ret = irecv_get_imei(client, imei);
				if (ret == IRECV_E_SUCCESS) printf("IMEI: %s\n", imei);
				else printf("Failed to get IMEI.\n");

				irecv_exit();
			}
			else if (!strcmp(arg, "-r"))
			{
				int ret;
				printf("\nReseting USB counters...\n");
				irecv_open_attempts(&client, 10);
				irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
				ret = irecv_reset_counters(client);
				if (ret == IRECV_E_SUCCESS) {
					printf("\nDone!\n\n");
				} else if (ret == IRECV_E_NO_DEVICE) {
					printf("\nNo device found.\n\n");
				} else {
					printf("\nFailed to reset USB counters...\n\n");
				}
				irecv_exit();
				irecv_reconnect(client, 10);
			}
			else if (!strcmp(arg, "-find"))
			{
				int ret;
				irecv_open_attempts(&client, 10);

				if (client->mode == kDfuMode)
				{	
					ret = irecv_get_device(client, &device);
					if (ret == IRECV_E_SUCCESS)
						printf("\n%s found in DFU Mode.\n\n", device->product);
					else
						printf("\nDevice found in DFU Mode.\n\n");
				} 
				else if (client->mode == kRecoveryMode1 || client->mode == kRecoveryMode2 || client->mode == kRecoveryMode3 || client->mode == kRecoveryMode4)
				{
					ret = irecv_get_device(client, &device);
					if (ret == IRECV_E_SUCCESS)
						printf("\n%s found in Recovery Mode.\n\n", device->product);
					else
						printf("\nDevice found in Recovery Mode.\n\n");
				}
				else
				{
					printf("\nNo device found in Recovery or DFU Mode.\n");
				}
			}
			else if (!strcmp(arg, "-detect"))
			{
				int ret;
				irecv_open_attempts(&client, 10);
				ret = irecv_get_device(client, &device);
				if (ret == IRECV_E_SUCCESS) 
					 if (argc >= 3) printf("%s", device->model);
					 else printf("\n%s\n", device->bid);
				else
					printf("\nNo device found.\n");
				irecv_exit();
			}
			else if (!strcmp(arg, "-getdeviceid"))
			{
				int ret;
				irecv_open_attempts(&client, 10);
				ret = irecv_get_device(client, &device);
				if (ret == IRECV_E_SUCCESS) 
					printf("%s", device->model);
				else
					printf("NoDeviceFound");
				irecv_exit();
			}
			else if (!strcmp(arg, "-getboardid"))
			{
				int ret;
				irecv_open_attempts(&client, 10);
				ret = irecv_get_device(client, &device);
				if (ret == IRECV_E_SUCCESS) 
					printf("%s", device->bid);
				else
					printf("NoDeviceFound");
				irecv_exit();
			}
			else if (!strcmp(arg, "-getdevicename"))
			{
				int ret;
				irecv_open_attempts(&client, 10);
				ret = irecv_get_device(client, &device);
				if (ret == IRECV_E_SUCCESS) 
					printf("%s", device->name);
				else
					printf("NoDeviceFound");
				irecv_exit();
			}
			else if (!strcmp(arg, "-kick"))
			{
				int ret;
				irecv_open_attempts(&client, 10);
				
				if (client->mode == kDfuMode || client->mode == kRecoveryMode1 || client->mode == kRecoveryMode2 || client->mode == kRecoveryMode3 || client->mode == kRecoveryMode4) 
				{
					printf("\nSetting auto-boot true\n");
					ret = irecv_setenv(client, "auto-boot", "true");
					if (ret != IRECV_E_SUCCESS)
						printf(" - Failed - \n");

					printf("\nSaving enviornment\n");
					ret = irecv_saveenv(client);
					if (ret != IRECV_E_SUCCESS)
						printf(" - Failed - \n");

					printf("\nRebooting...\n");
					ret = irecv_send_command(client, "reboot");
					if (ret != IRECV_E_SUCCESS)
						printf(" - Failed - \n");

					irecv_exit();
				}
				else
				{
					printf("\nNo Device found.\n");
				}
			}
			else if (!strcmp(arg, "-killitunes"))
			{
				printf("\nKilling iTunes.exe\n");
				system("TASKKILL /F /IM iTunes.exe > NUL");
				printf("\nKilling iTunesHelper.exe\n");
				system("TASKKILL /F /IM iTunesHelper.exe > NUL");
			}
			else if (!strcmp(arg, "-ss"))
			{
				printf("\nO.o HIDDEN COMMAND! :O\n\nKeep wondering what it did :P\n");
			}
			else
			{
				printf("\nInvalid command!\n");
			}
			return 0;
		}
	}
}

