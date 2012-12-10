## syringe-irecovery
A remake of iRecovery based off [syringe](https://github.com/Chronic-Dev/syringe) library.

### iRecovery
A libusb-based commandline utility that talks to iBoot/iBSS on iOS devices via USB.


### Usage

  iRecovery [args]

		-c <command>      Send a single command to client.
		-detect           Get board config. (eg. n90ap)
		-dfu              Poll device for DFU mode.
		-e                Send limera1n or steaks4uce [bootrom exploits].
		-ecid             Get the device ecid.
		-f <file>         Upload a file to client.
		-find             Find device in Recovery/iBoot or DFU mode.
		-g <var>          Grab a nvram variable from iBoot. (getenv)
		-i                Get device info. (CPID, ECID, etc.)
		-j <script>       Executes recovery shell script.
		-k <payload>      Send the 0x21,2 usb exploit [ < 3.1.2 iBoot exploit].
		-kick             Kick the device out of Recovery Mode.
		-r                Reset USB counters.
		-s                Start an interactive shell.
