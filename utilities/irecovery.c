/**
  * Syringe-based irecovery -- irecovery.c
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

#ifdef __APPLE__
#define READLINE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef READLINE
#include <readline/history.h>
#include <readline/readline.h>
#endif

#include "libirecovery.h"
#include "libpois0n.h"

#define FILE_HISTORY_PATH ".irecovery"
#define debug(...) fprintf(stderr, __VA_ARGS__)
static unsigned int quit = 0;

int received_cb(irecv_client_t client, const irecv_event_t* event);
int progress_cb(irecv_client_t client, const irecv_event_t* event);
int precommand_cb(irecv_client_t client, const irecv_event_t* event);
int postcommand_cb(irecv_client_t client, const irecv_event_t* event);
char *mode_to_string(int mode);


void print_progress_bar(double progress) {

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

void shell_usage() {
	printf("Usage:\n");
	printf("\t/upload <file>\tSend file to client.\n");
	printf("\t/exploit [file]\tSend usb exploit with optional payload\n");
	printf("\t/deviceinfo\tShow device information (ECID, IMEI, etc.)\n");
	printf("\t/help\t\tShow this help.\n");
	printf("\t/exit\t\tExit interactive shell.\n");
}

void parse_command(irecv_client_t client, unsigned char* command, unsigned int size) {
	char* cmd = strdup(command);
	char* action = strtok(cmd, " ");

	if (!strcmp(cmd, "/exit")) {
		quit = 1;
	} else

	if (!strcmp(cmd, "/help")) {
		shell_usage();
	} else

	if (!strcmp(cmd, "/upload")) {
		char* filename = strtok(NULL, " ");
		debug("Uploading files %s\n", filename);
		if (filename != NULL ) {
			irecv_send_file(client, filename, 0);
		}
	} else

	if (!strcmp(cmd, "/exploit")) {
		char* filename = strtok(NULL, " ");
		debug("Sending exploit %s\n", filename);
		if (filename != NULL ) {
			irecv_send_file(client, filename, 0);
		}
		irecv_send_exploit(client);
	} else

	if (!strcmp(cmd, "/execute")) {
		char* filename = strtok(NULL, " ");
		debug("Executing script %s\n", filename);
		if (filename != NULL ) {
			irecv_execute_script(client, filename);
		}
	}

	free(action);
}

#ifdef READLINE
void load_command_history() {
	read_history(FILE_HISTORY_PATH);
}

void append_command_to_history(char* cmd) {
	add_history(cmd);
	write_history(FILE_HISTORY_PATH);
}
#endif

void init_shell(irecv_client_t client)
{
	irecv_error_t error = 0;
	char *cmd = NULL;
#ifdef READLINE
	load_command_history();
#endif
	irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL );
	irecv_event_subscribe(client, IRECV_RECEIVED, &received_cb, NULL );
	irecv_event_subscribe(client, IRECV_PRECOMMAND, &precommand_cb, NULL );
	irecv_event_subscribe(client, IRECV_POSTCOMMAND, &postcommand_cb, NULL );

	while (!quit) {
#ifdef READLINE
		char* cmd = readline("> ");
#else
		printf("> ");
		cmd = malloc(512);
		if(!cmd) {
			abort();
		}
		memset(cmd, 0, 512);
		fgets(cmd, 512, stdin);
#endif
		if (cmd && *cmd) {
			error = irecv_send_command(client, cmd);
			if (error != IRECV_E_SUCCESS) {
				quit = 1;
			}
#ifdef READLINE
			append_command_to_history(cmd);
#endif
			free(cmd);
		}
	}
}

void print_usage(const char *argv0) {
	printf("iRecovery - Recovery Utility - Originally made by westbaer\n" \
			"Thanks to pod2g, tom3q, planetbeing, geohot, and posixninja.\n\n" \
			"This is based off syringe available at: http://github.com/posixninja/syringe\n" \
			"And iH8sn0w's syringe-irecovery: http://github.com/iH8sn0w/syringe-irecovery\n\n" \
			"Modified by Neal (@iNeal) - http://github.com/Neal/syringe-irecovery\n\n" \
			"Usage: %s [args]\n\n" \
			"  -c <command>      Send a single command to client.\n" \
			"  -detect           Get board config. (eg. n90ap)\n" \
			"  -dfu              Poll device for DFU mode.\n" \
			"  -e                Send limera1n or steaks4uce [bootrom exploits].\n" \
			"  -ecid             Get the device ecid.\n" \
			"  -f <file>         Upload a file to client.\n" \
			"  -find             Find device in Recovery/iBoot or DFU mode.\n" \
			"  -g <var>          Grab a nvram variable from iBoot. (getenv)\n" \
			"  -i                Get device info. (CPID, ECID, etc.)\n" \
			"  -j <script>       Executes recovery shell script.\n" \
			"  -k <payload>      Send the 0x21,2 usb exploit [ < 3.1.2 iBoot exploit].\n" \
			"  -kick             Kick the device out of Recovery Mode.\n" \
			"  -r                Reset USB counters.\n" \
			"  -s                Start interactive shell.\n" \
			"\n" , argv0);
	return;
}


int main(int argc, char* argv[]) {

	if(argc < 2)
	{
		print_usage(argv[0]);
	}
	else
	{
		char** pArg;
		for (pArg = argv + 1; pArg < argv + argc; ++pArg)
		{
			const char* arg = *pArg;
			
			if (!strcmp(arg, "-h") || !strcmp(arg, "-help"))
			{
				print_usage(argv[0]);
			}
			else if (!strcmp(arg, "-b"))
			{
				if (argc >= 4)
                {
                    int inDFU = 1;
                    int iniBoot = 1;
                    
                    irecv_init();
                    printf("Waiting for device in DFU mode...\n");
                    while (!inDFU) {
                        if (irecv_open(&client) == IRECV_E_SUCCESS) {
                            irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
                            if (client->mode == kDfuMode) {
                                irecv_close(client);
                                inDFU = 0;
                            }
                        }
                        sleep(1);
                    }
                    
                    irecv_open_attempts(&client, 10);
                    irecv_get_device(client, &device);
                    printf("Found %s\n", device->product);
                    irecv_close(client);
                    irecv_exit();
                    
                    pois0n_init();
                    pois0n_set_callback(&progress_cb, NULL);
                    if(!pois0n_is_ready() && !pois0n_is_compatible())
                        pois0n_injectonly();
                    pois0n_exit();
                    
                    sleep(2);
					irecv_init();
					irecv_open_attempts(&client, 10);
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					printf("Uploading iBSS to %s.\n", device->product);
					irecv_send_file(client, argv[2], 1);
#ifdef _WIN32
                    sleep(7);
#endif
                    client = irecv_reconnect(client, 0);
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					printf("Uploading iBSS payload to %s.\n", device->product);
                    irecv_send_file(client, argv[3], 0);
                    
                    sleep(1);
                    irecv_send_command(client, "go");
                    irecv_send_command(client, "go fbclear");
                    irecv_send_command(client, "go nvram set iKGD true");
                    irecv_send_command(client, "go fbecho Success!");
					irecv_exit();
                    
                } else {
					printf("usage: %s -p <iBSS> <payload>\n", argv[0]);
                }
			}
			else if (!strcmp(arg, "-e"))
			{
				irecv_init();
				irecv_open_attempts(&client, 10);
				if (client->mode == kDfuMode)
				{
					irecv_close(client);
					irecv_exit();
					pois0n_init();
					pois0n_set_callback(&progress_cb, NULL);
					if(!pois0n_is_ready() && !pois0n_is_compatible())
						pois0n_injectonly();
					pois0n_exit();
				}
				else
				{
					printf("No device found in DFU Mode.\n");
				}
			}
			else if (!strcmp(arg, "-k"))
			{
				if (argc >= 3) {
					irecv_error_t error;
					irecv_init();
					irecv_open_attempts(&client, 10);
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					printf("\nSending USB exploit...\n");
					error = irecv_send_file(client, argv[2],0);
					if (error == IRECV_E_SUCCESS) {
						irecv_send_exploit(client);
						printf("\nUSB exploit sent!\n");
					} else {
						printf("\nFailed to send the Exploit. Error: %d\n", (int) error);
					}
				} else {
					printf("usage: %s -k <payload>\n", argv[0]);
				}
			}
			else if (!strcmp(arg, "-s"))
			{
				irecv_error_t error;
				printf("Initializing...\n");
				irecv_init();
				irecv_open_attempts(&client, 10);
				error = irecv_get_device(client, &device);
				if (error == IRECV_E_SUCCESS) {
#ifndef READLINE
					printf("iBoot information: %s\n", client->serial);
#endif
					printf("Starting shell...\n");
					irecv_reset(client);
					client = irecv_reconnect(client, 2);
					irecv_set_interface(client, 0, 0);
					irecv_set_interface(client, 1, 1);
					init_shell(client);
				} else {
					printf("No device found. Error %d\n", (int) error);
				}
			}
			else if (!strcmp(arg, "-c"))
			{
				if (argc >= 3) {
					irecv_error_t error;
					irecv_init();
					irecv_open_attempts(&client, 10);
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					error = irecv_send_command(client, argv[2]);
					if (error == IRECV_E_SUCCESS)
						printf("Command Sent! \"%s\"\n", argv[2]);
					else
						printf("\nFailed to send command.\n");
					irecv_exit();
				} else {
					printf("usage: %s -c <command>\n", argv[0]);
				}
			}
			else if (!strcmp(arg, "-f"))
			{
				if (argc >= 3) {
					irecv_error_t error;
					irecv_init();
					if (irecv_open_attempts(&client, 10) != IRECV_E_SUCCESS) {
						printf("\nNo device found in Recovery or DFU Mode.\n");
						break;
					}
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					printf("Uploading file in %s Mode.\n", mode_to_string(client->mode));
					if (client->mode == kDfuMode)
						error = irecv_send_file(client, argv[2], 1);

					else if (client->mode == kRecoveryMode1 || client->mode == kRecoveryMode2 || client->mode == kRecoveryMode3 || client->mode == kRecoveryMode4)
						error = irecv_send_file(client, argv[2],0);

					else
						printf("\nNo device found in Recovery or DFU Mode.\n");
					
					irecv_exit();
				} else {
					printf("usage: %s -f <file>\n", argv[0]);
				}
			}
			else if (!strcmp(arg, "-g"))
			{
				if (argc >= 3) {
					irecv_error_t error;
					char* value = NULL;
					irecv_init();
					irecv_open_attempts(&client, 10);
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					error = irecv_getenv(client, argv[2], &value);
					if (error != IRECV_E_SUCCESS)
						printf("Failed to get the variable! Error: %d\n", irecv_strerror(error));
					else
						printf("%s\n", value);
					irecv_exit();
				} else {
					printf("usage: %s -g <var>\n", argv[0]);
				}
			}
			else if (!strcmp(arg, "-i"))
			{
				irecv_error_t error;
				int i;
				unsigned int cpid, bdid;
				unsigned char ecid[20], srnm[16], imei[16];
				irecv_init();
				irecv_open_attempts(&client, 10);
				printf("\n");

				if (argc >= 3 && (!strcmp(argv[2],"-serial"))) {
					error = irecv_get_cpid(client, &cpid);
					if (error == IRECV_E_SUCCESS) printf("iBoot info: %s\n", client->serial);
				}

				error = irecv_get_cpid(client, &cpid);
				if (error == IRECV_E_SUCCESS) printf("CPID: %d\n", cpid);

				error = irecv_get_bdid(client, &bdid);
				if (error == IRECV_E_SUCCESS) printf("BDID: %02d\n", bdid);

				error = irecv_get_ecid(client, ecid);
				if (error == IRECV_E_SUCCESS)
				{
					printf("ECID: ");
					for(i=0;i<16;i++) {
						printf("%c",ecid[i]);
					}
					printf("\n");
				}

				error = irecv_get_srnm(client, srnm);
				if (error == IRECV_E_SUCCESS) printf("SRNM: %s\n", srnm);

				error = irecv_get_imei(client, imei);
				if (error == IRECV_E_SUCCESS) printf("IMEI: %s\n", imei);

				irecv_exit();
			}
			else if (!strcmp(arg, "-r"))
			{
				irecv_reset_counters(client);
				irecv_reset(client);
			}
			else if (!strcmp(arg, "-j"))
			{
				if (argc >= 3) {
					irecv_error_t error;
					irecv_init();
					irecv_open_attempts(&client, 10);
					error = irecv_execute_script(client, argv[2]);
					if (error == IRECV_E_SUCCESS)
						printf("\nScript executed successfully!\n");
					else
						printf("\nFailed to execute script! Error: %d\n\n", irecv_strerror(error));
					irecv_exit();
				} else {
					printf("usage: %s -j <script>\n", argv[0]);
				}
			}
			else if (!strcmp(arg, "-aesdec"))
			{
				if (argc >= 3) {
					irecv_error_t error;
					char* iv = NULL;
					char* key = NULL;
					char* GoAesDecCommand = (char*) malloc (110);
					sprintf(GoAesDecCommand, "go aes dec %s", argv[2]);
					irecv_init();
					irecv_open_attempts(&client, 10);
					irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
					error = irecv_send_command(client, GoAesDecCommand);
					if (error == IRECV_E_SUCCESS) {
						irecv_getenv(client, "iv", &iv);
						irecv_getenv(client, "key", &key);
						if(argc == 3) {
							printf("IV: %s\n", iv);
							printf("KEY: %s\n", key);
						} else {
							printf("{\"KBAG\":\"%s\",\"IV\":\"%s\",\"KEY\":\"%s\"}", argv[2], iv, key);
						}
					}
					irecv_exit();
				} else {
					printf("usage: %s -aesdec <kbag>\n", argv[0]);
				}
			}
			else if (!strcmp(arg, "-ecid"))
			{
				irecv_error_t error;
				int i;
				unsigned char ecid[20];
				irecv_init();
				irecv_open_attempts(&client, 10);
				error = irecv_get_ecid(client, ecid);
				if (error == IRECV_E_SUCCESS)
				{
					for(i=0;i<16;i++)
						printf("%c",ecid[i]);

					printf("\n");
				}
				else printf("Failed to get the ECID. Error: %d\n", irecv_strerror(error));
				irecv_close(client);
			}
			else if (!strcmp(arg, "-platform"))
			{
				irecv_error_t error;
				unsigned int cpid;
				irecv_init();
				irecv_open_attempts(&client, 10);
				error = irecv_get_cpid(client, &cpid);
				if (error == IRECV_E_SUCCESS) printf("s5l%dx\n", cpid);
				else printf("Failed to get CPID.\n");
				irecv_close(client);
			}
			else if (!strcmp(arg, "-dfu"))
			{
				char *blah = "Connect device in DFU mode.";

				irecv_init();
				while (poll_device_for_dfu(blah))
					sleep(1);

				irecv_init();
				irecv_open_attempts(&client, 10);
				irecv_get_device(client, &device);
				fflush(stdout);
				printf("%s [Found %s]\n", blah, device->product);
				irecv_close(client);
			}
			else if (!strcmp(arg, "-find"))
			{
				irecv_error_t error;
				irecv_init();
				irecv_open_attempts(&client, 10);
				error = irecv_get_device(client, &device);
				if (error == IRECV_E_SUCCESS) {
					printf("\n%s found in %s Mode.\n\n", device->product, mode_to_string(client->mode));
				} else {
					printf("\nNo device found.\n");
				}
				irecv_exit();
			}
			else if (!strcmp(arg, "-detect"))
			{
				irecv_error_t error;
				irecv_init();
				irecv_open_attempts(&client, 10);
				error = irecv_get_device(client, &device);
				if (error == IRECV_E_SUCCESS)
					printf("%s", device->model);
				else
					printf("\nNo device found.\n");
				irecv_exit();
			}
			else if (!strcmp(arg, "-getboardid"))
			{
				irecv_error_t error;
				irecv_init();
				irecv_open_attempts(&client, 10);
				error = irecv_get_device(client, &device);
				if (error == IRECV_E_SUCCESS) 
					printf("%s", device->model);
				else
					printf("\nNo device found.\n");
				irecv_exit();
			}
			else if (!strcmp(arg, "-getdeviceid"))
			{
				irecv_error_t error;
				irecv_init();
				irecv_open_attempts(&client, 10);
				error = irecv_get_device(client, &device);
				if (error == IRECV_E_SUCCESS) 
					printf("%c%c%c", device->model[0], device->model[1], device->model[2]);
				else
					printf("\nNo device found.\n");
				irecv_exit();
			}
			else if (!strcmp(arg, "-kick"))
			{
				irecv_error_t error;
				irecv_init();
				irecv_open_attempts(&client, 10);
				if (client->mode == kRecoveryMode1 || 
					client->mode == kRecoveryMode2 || 
					client->mode == kRecoveryMode3 || 
					client->mode == kRecoveryMode4 ||
					client->mode == kDfuMode) {

					printf("\nSetting auto-boot true\n");
					error = irecv_setenv(client, "auto-boot", "true");
					if (error != IRECV_E_SUCCESS)
						printf(" - Failed - \n");

					printf("\nSaving enviornment\n");
					error = irecv_saveenv(client);
					if (error != IRECV_E_SUCCESS)
						printf(" - Failed - \n");

					printf("\nRebooting...\n");
					error = irecv_send_command(client, "reboot");
					if (error != IRECV_E_SUCCESS)
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
#ifdef __APPLE__
				system("killall -9 iTunesHelper");
#endif
#ifdef _WIN32
				system("TASKKILL /F /IM iTunes.exe > NUL 2>&1");
				system("TASKKILL /F /IM iTunesHelper.exe > NUL 2>&1");
#endif
			}
			else
			{
				printf("\nInvalid command!\n");
			}
			return 0;
		}
	}
}


char *mode_to_string(int mode)
{
	if (mode == kDfuMode)
		return "DFU";

	if (mode == kRecoveryMode1 ||
		mode == kRecoveryMode2 ||
		mode == kRecoveryMode3 ||
		mode == kRecoveryMode4)
		return "Recovery/iBoot";

	return "UNKNOWN";
}

int poll_device_for_dfu(const char *text)
{
	static int blah;
	printf("%s [%u]\r", text, blah);
	if (irecv_open(&client) != IRECV_E_SUCCESS) {
		blah++;
		return 1;
	}
	irecv_event_subscribe(client, IRECV_PROGRESS, &progress_cb, NULL);
	if (client->mode != kDfuMode) {
		irecv_close(client);
		blah++;
		return 1;
	}
	return 0;
}

int progress_cb(irecv_client_t client, const irecv_event_t* event) {
	if (event->type == IRECV_PROGRESS) {
		print_progress_bar(event->progress);
	}
	return 0;
}

int received_cb(irecv_client_t client, const irecv_event_t* event) {
	if (event->type == IRECV_RECEIVED) {
		int i = 0;
		int size = event->size;
		char* data = event->data;
		for (i = 0; i < size; i++) {
			printf("%c", data[i]);
		}
	}
	return 0;
}

int precommand_cb(irecv_client_t client, const irecv_event_t* event) {
#ifdef READLINE
	if (event->type == IRECV_PRECOMMAND) {
		irecv_error_t error = 0;
		if (event->data[0] == '/') {
			parse_command(client, event->data, event->size);
			return -1;
		}
	}
#endif
	return 0;
}

int postcommand_cb(irecv_client_t client, const irecv_event_t* event) {
	char* value = NULL;
	char* action = NULL;
	char* command = NULL;
	char* argument = NULL;
	irecv_error_t error = IRECV_E_SUCCESS;

	if (event->type == IRECV_POSTCOMMAND) {
		command = strdup(event->data);
		action = strtok(command, " ");
		if (!strcmp(action, "getenv")) {
			argument = strtok(NULL, " ");
			error = irecv_getenv(client, argument, &value);
			if (error != IRECV_E_SUCCESS) {
				debug("%s\n", irecv_strerror(error));
				free(command);
				return error;
			}
			printf("%s\n", value);
			free(value);
		}

		if (!strcmp(action, "reboot")) {
			quit = 1;
		}
	}

	if (command)
		free(command);
	return 0;
}
