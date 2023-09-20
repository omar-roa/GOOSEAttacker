# Captures

## DoS Subscriber
The start of the attack is observed at time ~130 with a field reserved at 1.<br>
The attack concludes at time ~730.<br>
[Wireshark capture](https://udeaeduco-my.sharepoint.com/:u:/g/personal/omar_roa_udea_edu_co/EZWXwV2i1ANJroyBKBCoOfIBYYCROiDsrk572tHGHH1OXw?e=3tNgXR)

## DoS Publisher
The start of the attack is observed at time ~108 with a field reserved at 1.<br>
The attack concludes at time ~709.<br>
[Wireshark capture](https://udeaeduco-my.sharepoint.com/:u:/g/personal/omar_roa_udea_edu_co/ESJUZGcbifNIg4FsO0v1g2IBvyeY9Y9mu-8K1Tg9x2ZxOA)

## TRACK +1 Single Shot
The start of the attack is observed at time ~141 with a field reserved at 2.<br>
At time ~553, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>
The attack concludes at time ~734.<br>
[Wireshark capture](https://udeaeduco-my.sharepoint.com/:u:/g/personal/omar_roa_udea_edu_co/EbVVkCGwAoFDo63Bds8yDxQBKb-Adr9wxqKyYBqRqnSQAg?e=NB6i6w)

## TRACK +1 Multiple Shots
The start of the attack is observed at time ~115 with a field reserved at 2.<br>
At time ~249, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>

At time ~444, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>

At time ~446, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>

At time ~448, the shot is triggered, and the attack responds to both changes in stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
No LED activation is evident in the IED.<br>

The attack concludes at time ~709.<br>
[Wireshark capture](https://udeaeduco-my.sharepoint.com/:u:/g/personal/omar_roa_udea_edu_co/ERNnSPDvjEVBu8TeC2qxXK8BW40kx60iPTbKCb9erwah3A?e=KhaQzc)

## REPLAY Single Shot (Replay in 500 seconds)
At time ~221, the shot is triggered, and the attack responds to the change in stNum by storing the packet for later manipulation and resending.<br>
The packet is sent at time ~721 with a higher stNum than the actual one and field reserved at 3. In the IED, the LED is turned on and remains on for the
remainder of the test.<br>
[Wireshark capture](https://udeaeduco-my.sharepoint.com/:u:/g/personal/omar_roa_udea_edu_co/EYpV6O319LlMteA4EaV9QTwBvvUuU_aLc_Ozdhw7Mk5cMw?e=x4tjMV)

## REPLAY Multiple Shots (Replay in 500 seconds)
At time ~278, the shot is triggered, and the attack responds to the change in stNum by storing the packet for later manipulation and resending.<br>
At time ~387, the shot is triggered again.<br>
At time ~418, the shot is triggered again.<br>
At time ~419, the shot is triggered again.<br>
At time ~421, the shot is triggered again.<br>
The packet is sent at time ~778 with a higher stNum than the actual one and field reserved at 3. In the IED, the LED is turned on and remains on for the
remainder of the test.<br>
[Wireshark capture](https://udeaeduco-my.sharepoint.com/:u:/g/personal/omar_roa_udea_edu_co/EZkgufS3tupAvr5mhnZKyq8BunUD_fAwAKbW9n7W5WdQZw?e=Yn04k2)

## FDI Without Shot
At time ~141, the FDI begins with a reserved value of 4. The stNum is higher than the actual value, and it initiates the sqNum at 0, gradually increasing it.
The LED in the IED is observed to be on.<br>
There is no evidence of the LED turning off in the IED.<br>
The attack concludes at time ~740, and the LED remains on.<br>
[Wireshark capture](https://udeaeduco-my.sharepoint.com/:u:/g/personal/omar_roa_udea_edu_co/EcdgslAXu_1GlFdF-BkmkSsBULPOmRMaGkHIZB9HOsV-xA?e=XeLkyD)

## FDI Single Shot
At time ~130, the FDI begins with a reserved value of 4. The stNum is higher than the actual value, and it initiates the sqNum at 0, gradually increasing it.<br>
The LED in the IED is observed to be on.<br>
At time ~437, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum.<br>
There is no evidence of the LED turning off in the IED.<br>
The attack concludes at time ~729, and the LED remains on.<br>
[Wireshark capture](https://udeaeduco-my.sharepoint.com/:u:/g/personal/omar_roa_udea_edu_co/EUtnV8ecqENJjQXgmMqcThcBvLO50YGRIaBLjw5tAjcIJQ?e=SFsIkU)

## FDI Multiple Shots
At time ~127, the FDI begins with a reserved value of 4. The stNum is higher than the actual value, and it initiates the sqNum at 0, gradually increasing it.
The LED in the IED is observed to be on.<br>

At time ~202, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum. There is no evidence of the LED turning off in the IED.<br>

At time ~459, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum. There is no evidence of the LED turning off in the IED.<br>

At time ~461, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum. There is no evidence of the LED turning off in the IED.<br>

At time ~462, the shot is triggered, and the attack responds to both changes in the stNum, preempting with a higher stNum in both cases,
while resetting the sqNum. There is no evidence of the LED turning off in the IED.<br>

The attack concludes at time ~721, and the LED remains on.<br>
[Wireshark capture](https://udeaeduco-my.sharepoint.com/:u:/g/personal/omar_roa_udea_edu_co/EQ9RMWdyRoVMldwL0hVM74QBjdKeBerVzepWXNWVe4rDpg?e=jOAZ3s)
