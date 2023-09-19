# Captures

## TRACK +1 Single Shot
The start of the attack is observed at time ~122 with a tag reserved at 2.<br>
At time ~314, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>
The attack concludes at time ~722.<br>
[Wireshark capture](https://drive.google.com/file/d/1q3NpGLjBJsJ8kYkyGis_Pnjo2hwzSpex/view?usp=drive_link)

## TRACK +1 Multiple Shots
The start of the attack is observed at time ~148 with a tag reserved at 2.<br>
At time ~221, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>

At time ~365, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>

At time ~534, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>

At time ~668, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>

The attack concludes at time ~740.<br>
[Wireshark capture](https://drive.google.com/file/d/1j9dl6Rxrd6hk_OiBv1YAOAtwAJjOYYjF/view?usp=drive_link)

## REPLAY Single Shot
At time ~163, the shot is triggered, and the attack responds to the change in stNum by storing the packet for later manipulation and resending.<br>
The packet is sent at time ~463 with a higher stNum than the actual one and reserved at 4. In the IED, the LED is turned on and remains on for the
remainder of the test.<br>
[Wireshark capture](https://drive.google.com/file/d/1qxmtNb4SXhpZmQ29JS2BP322jdhXOnLW/view?usp=drive_link)

## REPLAY Multiple Shots
At time ~147, the shot is triggered, and the attack responds to the change in stNum by storing the packet for later manipulation and resending.<br>
At time ~249, the shot is triggered again.<br>
At time ~347, the shot is triggered again.<br>
At time ~350, the shot is triggered again.<br>
At time ~353, the shot is triggered again.<br>
The packet is sent at time ~647 with a higher stNum than the actual one. In the IED, the LED is turned on and remains on for the
remainder of the test.<br>
[Wireshark capture](https://drive.google.com/file/d/1e9-GTMkkeM7-Zhlp0iuoeTIfpfX_IrB8/view?usp=drive_link)

## FDI Without Shot
At time ~136, the FDI begins with a reserved value of 5. The stNum is higher than the actual value, and it initiates the sqNum at 0, gradually increasing it.
The LED in the IED is observed to be on.<br>
There is no evidence of the LED turning off in the IED.<br>
The attack concludes at time ~735, and the LED remains on.<br>
[Wireshark capture](https://drive.google.com/file/d/10iKn0DsEVR06KYht21ayWodgFSi4fUOl/view?usp=drive_link)

## FDI Single Shot
At time ~137, the FDI begins with a reserved value of 5. The stNum is higher than the actual value, and it initiates the sqNum at 0, gradually increasing it.<br>
The LED in the IED is observed to be on.<br>
At time ~381, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
There is no evidence of the LED turning off in the IED.<br>
The attack concludes at time ~730, and the LED remains on.<br>
[Wireshark capture](https://drive.google.com/file/d/1Y-2RKQ0HWmgWZyPEg8DKCklEciQ2Z6s2/view?usp=drive_link)

## FDI Multiple Shots
At time ~133, the FDI begins with a reserved value of 5. The stNum is higher than the actual value, and it initiates the sqNum at 0, gradually increasing it.
The LED in the IED is observed to be on.<br>

At time ~247, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum. There is no evidence of the LED turning off in the IED.<br>

At time ~432, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum. There is no evidence of the LED turning off in the IED.<br>

At time ~434, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum. There is no evidence of the LED turning off in the IED.<br>

At time ~436, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum. There is no evidence of the LED turning off in the IED.<br>

The attack concludes at time ~729, and the LED remains on.<br>
[Wireshark capture](https://drive.google.com/file/d/1HbHaeE0ELKEAjRN68R8bV9_biX0ll5iM/view?usp=drive_link)
