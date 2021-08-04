/*
Add descriptions to interactions between nearbyd and the kernel to see what U1 is doing.
Toggle flight mode to see all mach annotations.

Attach as follows:

   frida -U nearbyd --no-pause -l rose_sniff_kernel.js

Change logging settings in the constructor.

*/

class CustomRoseController {

    constructor() {

        /*** INITIALIZE SCRIPT ***/

        // Connection ID changes with every nearbyd restart!
        // But we set them automatically on one of the first calls.
        this.AppleSPUUserClient_port = 0;
        this.AppleSPURoseDriverUserClient_port = 0;

        // TODO disable/enable mach debugging, lots of output!
        this.debug_mach = false;
        this.mach_truncate_size = 0x40;
        this.mach_remove_xpc = true;

        // TODO disable/enable IOKit additional arguments
        this.debug_iokit = true;

        this._data_ptr = Memory.alloc(0x1000);  // reusable memory pointer

        this.ios_version = "arm64e_14.2.1";  // TODO adjust version here!
    }


    /*
    Script preparation, needs to be called in standalone usage.
    Separated from constructor for external script usage.
    */
    prepare() {

        var self = this;

        // Crash logs will only be written in internal builds.
        self._nearbyd_base = Module.getBaseAddress('nearbyd');

        // Set the correct symbols
        self.setSymbols(self.ios_version);

        // gets IOKit ports for better printing
        self.getIOKitPorts();
        self.logIOKit();
        if (self.debug_mach) {
            self.logMach();
        }
    }


    /*
    Somewhat dirty hack to get the correct mach ports but works for me :)
    Still more stable than Dave's solution, no idea why that hangs :/
    */
    getIOKitPorts() {

        var self = this;

        /*
         Most function calls need a pointer to RoseController later on, save it.
        */
        var _RoseController_PerformCommand_addr = Module.getExportByName('RoseControllerLib', '_ZN14RoseController14PerformCommandEhPKhmPvmPmy');
        var _RoseController_ptr = 0;
        Interceptor.attach(_RoseController_PerformCommand_addr, {
            onEnter: function() {
                if (! self._RoseController_ptr) {
                    console.log('  * LibRoseController: PerformCommand, saving RoseController pointer and IOConnection');
                    self._RoseController_ptr = new NativePointer(this.context.x0);
                    // offset in struct, hope it's generic across versions
                    self.AppleSPURoseDriverUserClient_port = self._RoseController_ptr.add(480).readU16();
                }
            }
        });

        /*
         We also want to talk to the generic AppleSPUUserClient via IOKit but there are no exports in
         nearbyd, so we need to hook a function by address.

         This function here can be found by looking for the string "com.apple.nearbyd.RoseSupervisorCommandError".
        */

        Interceptor.attach(self._RoseSupervisorCommand_addr, {
            onEnter: function() {
                if (! self.AppleSPUUserClient_port) {
                    console.log('  * nearbyd: saving RoseSupervisorCommand IOConnection');
                    self.AppleSPUUserClient_port = this.context.x0.add(8).readU16();
                }
            }
        });
    }




    /*
    Log all function calls to the kernel and provide more information.
    Both, IOKit and raw mach messages, but IOKit is more readable :)
    */
    logIOKit() {

        /*
         RoseControllerLib communicates via IOKit, so let's also print that information.

         IOConnectCallMethod(mach_port_t connection, uint32_t selector, const uint64_t *input, uint32_t inputCnt,
                    const void *inputStruct, size_t inputStructCnt, uint64_t *output,
                    uint32_t *outputCnt, void *outputStruct, size_t *outputStructCnt)

          TODO double-check that IOConnectCallStructMethod is also covered by this

        */

        var self = this;

        var _IOConnectCallMethod_addr = Module.getExportByName('IOKit', 'IOConnectCallMethod');
        // might have async issues but works most of the time
        this.outputStruct = 0;
        this.outputStructCnt = 0;
        //this.performCommandInput = Memory.alloc(16);  // save this to call performCommand later on
        Interceptor.attach(_IOConnectCallMethod_addr, {
            onEnter: function(args) {

                var connection = args[0];
                var selector = parseInt(args[1]);
                var inputCnt = parseInt(args[3]);
                var inputStructCnt = parseInt(args[5]);
                this.outputStruct = args[8];
                this.outputStructCnt = args[9];


                /*
                console.log('Backtrace:\n' +
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n') + '\n');
                */


                connection = parseInt(connection); // convert to int for matching

                // Backtrace would always be via  nearbyd!0x1b6c94 (iOS 14.1), which is
                // related to com.apple.nearbyd.RoseSupervisorCommand, and it maps to another
                // IOKit service!

                if (connection == self.AppleSPUUserClient_port) {
                    switch(selector) {
                    case  0:
                     console.log("   - AppleSPUUserClient::extTestMethod()");
                     break;
                    case  1:
                     console.log("   - AppleSPUUserClient::extSetPropertyMethod()");
                     self.print_property(args[2].readU8());
                     console.log(args[4].readByteArray(parseInt(args[5])));
                     break;
                    case  2:
                     console.log("   - AppleSPUUserClient::extGetPropertyMethod()");
                     self.print_property(args[2].readU8());
                     // get is only printed on exit
                     break;
                    case  3:
                     console.log("   - AppleSPUUserClient::extPerformCommandMethod()");
                     self.print_iokit_args(args);
                     self.print_supervisor_command(args[2].readU8());
                     break;
                    case  4:
                     console.log("   - AppleSPUUserClient::extSetNamedPropertyMethod()");
                     break;
                    case  5:
                     console.log("   - AppleSPUUserClient::extGetNamedPropertyMethod()");
                     break;
                    }
                }
                // Print mappings to sMethods
                else if (connection == self.AppleSPURoseDriverUserClient_port) {
                    switch(selector) {
                    case  0:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseLoadFirmware()");
                     // called via RoseController::DownloadCustomFirmware -> RoseController::DownloadCustomFirmwareAsync
                     break;
                    case  1:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseGetInfo()");
                     break;
                    case  2:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseReset()");
                     break;
                    case  3:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseEnterCommandMode()");
                     break;
                    case  4:
                     console.log("   - AppleSPURoseDriverUserClient::extRosePing()");
                     break;
                    case  5:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseTx()");
                     self.print_iokit_args(args);
                     break;
                    case  6:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseTimeSync()");
                     break;
                    case  7:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseGetSyncedTime()");
                     break;
                    case  8:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseGetProperty()");
                     self.print_rose_property(args[2].readU8());
                     break;
                    case  9:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseSetProperty()");
                     self.print_rose_property(args[2].readU8());
                     console.log(args[4].readByteArray(parseInt(args[5])));
                     break;
                    case 10:
                     console.log("   - AppleSPURoseDriverUserClient::extRosePerformInternalCommand()");
                     break;
                    case 11:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseCacheFirmwareLogs()");
                     break;
                    case 12:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseDequeueFirmwareLogs()");
                     break;
                    case 13:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseTriggerCoredump()");
                     break;
                    case 14:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseDequeueCoredump()");
                     break;
                    case 15:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseCoredumpInfo()");
                     break;
                    case 16:
                     console.log("   - AppleSPURoseDriverUserClient::extRosePowerOn()");
                     break;
                    case 17:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseReadPowerState()");
                     break;
                    case 18:
                     console.log("   - AppleSPURoseDriverUserClient::extRoseConfigureFirmwareLogCache()");
                     break;
                    }
                }
                // Still print sth on unknown calls
                // Each time when starting AirDrop we get a new connection (with new ID)
                else {
                        console.log('  * IOConnectCallMethod(connection: ' + connection + ', selector: ' + selector + ', inputCnt: ' + inputCnt + ', ...)');
                }

                // Prints the plain params in hex, but that wasn't very helpful in our case.
                //console.log(this.context.x2.readByteArray(inputCnt));

                // Prints the connection struct, very helpful to figure out extRoseTx Commands!
                if (self.debug_iokit && inputStructCnt > 0) {
                    var inputStruct = new NativePointer(this.context.x4);
                    console.log('           v---- IOKit input struct ----');
                    console.log(inputStruct.readByteArray(inputStructCnt));
                }

            },

            // also read the response, works now :)
            onLeave: function(r) {

                // read count if not null
                if (this.outputStructCnt != "0x0") {
                    this.outputStructCnt = this.outputStructCnt.readU8();
                }

                if (self.debug_iokit && this.outputStructCnt > 0) {
                    console.log('           v---- IOKit output struct ----');
                    console.log(this.outputStruct.readByteArray(this.outputStructCnt));
                    //outputStruct = new NativePointer(outputStruct);
                    //console.log(outputStruct.readByteArray(outputStructCnt));
                }
            }
        });
    }

    print_iokit_args(args) {
        if (this.debug_iokit) {
             //console.log("     !!! extra info, command found !!!");
             console.log("       > connection      " +  args[0]);
             console.log("       > selector        " +  args[1]);
             console.log("       > input           " +  args[2]);
             console.log("       > inputCnt        " +  args[3]);
             console.log("          v ");
             console.log(args[2].readByteArray(parseInt(args[3])));
             console.log("       > inputStruct     " +  args[4]);
             console.log("       > inputStructCnt  " +  args[5]);
             console.log("       > output          " +  args[6]);
             console.log("       > outputCnt       " +  args[7]);
             console.log("       > outputStruct    " +  args[8]);
             if (args[8] != "0x0") {
                console.log("       > outputStructCnt*" +  args[9].readU64());
             }
        }
    }


    // All of this seems to be handled directly in the AOP
    print_property(property_id) {
        switch(property_id) {
            case 208:
             console.log("    ~ SPMISettings");
             break;
            case 209:
             console.log("    ~ UWBCommsRoute");
             break;
            case 210:
             console.log("    ~ BeaconWhitelist");
             break;
            case 211:
             console.log("    ~ R1MacAddress");
             break;
            case 212:
             console.log("    ~ AllowR1Sleep");
             break;
            case 213:
             console.log("    ~ CalDataPushed");
             break;
            case 214:
             console.log("    ~ CmdQueueClearAllowed");
             break;
            case 215:
             console.log("    ~ LogVerbose");
             break;
            case 216:
             console.log("    ~ RoseAOPHello");
             break;
            default:
             console.log("    ~ UNKNOWN " + property_id);
             break;
        }
    }

    // Shown during chip boot, needs `triggerCrashLog();`
    print_rose_property(property_id) {
        switch(property_id) {
            case 208:
             console.log("    ! GetBoardID");
             break;
            case 209:
             console.log("    ! GetChipID");
             break;
            case 210:
             console.log("    ! GetECID");
             break;
            case 211:
             console.log("    ! GetBootNonceHash");
             break;
            case 214:
             console.log("    ! GetBootMode");
             break;
            case 215:
             console.log("    ! GetHostBootNonce");
             break;
            case 216:
             console.log("    ! GetProductionMode");
             break;
            case 217:
             console.log("    ! GetSecureMode");
             break;
            case 218:
             console.log("    ! GetSecurityDomain");
             break;
            case 219:
             console.log("    ! GetMinimumEpoch");
             break;
            case 220:
             console.log("    ! GetDebugInfo::SecureROMStatus");
             break;
            case 221:
             console.log("    ! GetChipRevision");
             break;
            default:
             console.log("    ! UNKNOWN");
             break;
        }
    }

    print_supervisor_command(command_id) {
        command_id = String.fromCharCode(command_id); // convert to string representation

        switch(command_id) {
            case '0':
              console.log("    + PingCommand");  //TODO there's this null case but no idea how to represent... maybe it's \x30, maybe it's \x00
              break;
            case ' ':
              console.log("    + RosePassthrough");
              break;
            case '!':
              console.log("    + NewServiceRequest");  // starts with 2 bytes ticket ID
              break;
            case '"':
              console.log("    + TriggerRangingStart");
              break;
            case '#':
              console.log("    + TriggerRangingStop");
              break;
            case '$':
              console.log("    + CancelServiceRequest");  // 2 bytes ticket ID
              break;
            case '%':
              console.log("    + HelloCommand");
              break;
            case '&':
              console.log("    + GetPowerStats");
              break;
            case '\'':
              console.log("    + ResetJobs");
              break;
            case '(':
              console.log("    + APCheckIn");
              break;
            case ')':
              console.log("    + APGoodbye");
              break;
            case '*':
              console.log("    + ActivateTimeSync");
              break;
            case '+':
              console.log("    + UpdateSessionData");
              break;
            case '.':
              console.log("    + EmulatedRosePacket");
              break;
            case '/':
              console.log("    + EmulatedBTData");
              break;
            case ',':
            case '-':
            default:
              console.log("    + <Unknown Command Type>");
              break;
        }
    }


    /*
    Even RoseControllerLib sends a raw Mach message :/ So let's also hook this to double-check what we're missing.
    */
    logMach() {
     /*

         mach_msg_return_t __cdecl mach_msg(mach_msg_header_t *msg, mach_msg_option_t option, mach_msg_size_t send_size,
         mach_msg_size_t rcv_size, mach_port_name_t rcv_name, mach_msg_timeout_t timeout, mach_port_name_t notify)

         typedef	struct
         {
              mach_msg_bits_t	msgh_bits;
              mach_msg_size_t	msgh_size;
              mach_port_t		msgh_remote_port;
              mach_port_t		msgh_local_port;
              mach_msg_size_t 	msgh_reserved;
              mach_msg_id_t		msgh_id;  (0x14)
         } mach_msg_header_t;

         ... I think we need to add 0x18 to be at the body :)

         typedef struct
         {
                mach_msg_header_t       header;
                mach_msg_body_t         body;
         } mach_msg_base_t;

        */


        var self = this;


        var _mach_msg_addr = Module.getExportByName('libSystem.B.dylib', 'mach_msg');

        // TODO this might again run into runtime issues but also works most of the time
        // not sure if there could be vars in the interceptor itself?
        this._mach_msg_body_ptr;
        this._mach_msg_rcv_size;
        this._mach_msg_snd_size;
        this._mach_is_xpc = false;

        Interceptor.attach(_mach_msg_addr, {

            // parse what we send
            onEnter: function(args) {

                this._mach_is_xpc = false;
                this._mach_msg_body_ptr = this.context.x0.add(0x18);
                if (self.mach_remove_xpc && this._mach_msg_body_ptr.readU32() == 1079529539) { // Integer corresponding to "CPX@"
                    console.log('  * mach_msg(XPC, skipping for perf)');
                    this._mach_is_xpc = true;
                } else {
                    console.log('  * mach_msg(msg: ' + args[0] + ', option: ' + args[1] + ', send_size: ' +
                        args[2] + ', rcv_size: ' + args[3] + ', rcv_name port: ' + args[4] + ', timeout: ' + args[5] +
                        ', notify port: ' + args[6] + ')');

                    // get send_size bytes of body
                    this._mach_msg_snd_size = parseInt(args[2]);
                    if (this._mach_msg_snd_size > 0 && this._mach_msg_snd_size < self.mach_truncate_size) {
                        console.log('           v---- mach_msg input ----');
                        console.log(this._mach_msg_body_ptr.readByteArray(this._mach_msg_snd_size));
                    } else if (this._mach_msg_snd_size > 0) {
                        console.log('           v---- mach_msg input (truncated) ----');
                        console.log(this._mach_msg_body_ptr.readByteArray(self.mach_truncate_size));
                    }

                    // keep receive_size info for later
                    this._mach_msg_rcv_size = parseInt(this.context.x3);
                }
            },

            // parse what we receive in response
            // as far as I understand the original mach_msg body is overwritten on return
            onLeave: function(r) {

                //console.log(r); // it's only 0x0 for success, not interesting to print

                if ( ! (self.mach_remove_xpc && this._mach_is_xpc)) { // skip XPC messages if mach_remove_xpc=true and _mach_is_xpc=true

                    if (this._mach_msg_rcv_size > 0 && this._mach_msg_rcv_size < self.mach_truncate_size) {
                        console.log('           v---- mach_msg output ----');
                        console.log(this._mach_msg_body_ptr.readByteArray(this._mach_msg_rcv_size));
                    } else if (this._mach_msg_rcv_size > 0) {
                        console.log('           v---- mach_msg output (truncated) ----');
                        console.log(this._mach_msg_body_ptr.readByteArray(self.mach_truncate_size));
                    }
                }
            }
        });
    }

    /*
    Version-specific symbols, needs to be adjusted for every version.
    */
    setSymbols(ios_version) {

        var self = this;

        if (ios_version == "arm64e_13.3") {
            console.log("  * Set symbols to A12+ iOS 13.3");

            self._RoseSupervisorCommand_addr = self._nearbyd_base.add(0x141874);  // iOS 13.3, iPhone 11
        }

        // tested on an iPhone 11+12
        else if (ios_version == "arm64e_14.1") {
            console.log("  * Set symbols to A12+ iOS 14.1");

            self._RoseSupervisorCommand_addr = self._nearbyd_base.add(0x1B6BEC);  // iOS 14.1, iPhone 11 + 12
        }

        // tested on an iPhone 12
        else if (ios_version == "arm64e_14.2.1") {
            console.log("  * Set symbols to A12+ iOS 14.2.1");

            self._RoseSupervisorCommand_addr = self._nearbyd_base.add(0x1D5E58);  // iOS 14.1, iPhone 11 + 12
        }

        // tested on an iPhone 12
        else if (ios_version == "arm64e_14.3") {
            console.log("  * Set symbols to A12+ iOS 14.3");

            self._RoseSupervisorCommand_addr = self._nearbyd_base.add(0x1F32E0);
        }
    }



    // Export class methods for Frida
    makeExports() {
        var self = this;
        return {
            setsymbols: (ios_version) => {return self.setSymbols(ios_version)},
            prepare: () => {return self.prepare()},
        }
    }

}

var r = new CustomRoseController();

// Prepare the target function
r.prepare(); //call this when standalone

// Required to interact with Python ...
rpc.exports = r.makeExports();
rpc.exports.r = CustomRoseController;