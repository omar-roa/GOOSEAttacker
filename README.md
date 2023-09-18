# A GOOSE Attacker Tool for IEC61850
The digitization of critical infrastructures, such as electric infrastructures, introduces both advantages and vulnerabilities, particularly within Digital Electric Substations (DES) operating under the IEC 61850. Although there exist measures such as the IEC 62351 standard, there remain significant security risks are still present, including a computational cost that often exceeds the processing capabilities of standard devices and a common lack of cybersecurity knowledge among operators. This work focuses on the Generic Object-Oriented Substation Event (GOOSE) protocol and its associated vulnerabilities. The paper highlights the need for generating comprehensive datasets that not only include typical substation traffic but also simulate a diverse range of cyberattacks. The primary contribution of this work is the creation of a tool that emulates potential GOOSE attacks within a DES environment, thereby providing valuable resources for testing and developing robust detection and mitigation strategies. The tool marks malicious traffic, stores packet captures, and can be customized for specific attacks and scenarios. By facilitating a more thorough understanding of potential threats, this research underscores the urgency for a collaborative effort among industrial, academic, and governmental entities to enhance cybersecurity in critical infrastructures.

## DoS
[DoS Flowchart]("Goose Attacker Tool/Flowcharts/DoS - EN.png")
In this case, the attacker aims to overwhelm the target system with numerous requests, causing partial or complete disruption of its functionality. In the context of digital substations, various strategies are documented in the literature that can be used to incapacitate an IED. These strategies span from the transmission of malformed GOOSE frame bursts to the employment of tools designed to exploit protocol vulnerabilities present within SED *. The repercussions for the targeted device can vary, extending from total network function disablement to management loss or a noticeable delay in message response times.


*S. E. Quincozes, C. Albuquerque, D. Passos, and D. Mossé, “A survey on intrusion detection and prevention systems in digital substations,” Comput. Networks, vol. 184, no. September 2020, p. 107679, Jan. 2021, doi: 10.1016/j.comnet.2020.107679.
T. Nguyen, S. Wang, M. Alhazmi, M. Nazemi, A. Estebsari, and P. Dehghanian, “Electric Power Grid Resilience to Cyber Adversaries: State of the Art,” IEEE Access, vol. 8, pp. 87592–87608, 2020, doi: 10.1109/ACCESS.2020.2993233.
F. Li, X. Yan, Y. Xie, Z. Sang, and X. Yuan, “A Review of Cyber-Attack Methods in Cyber-Physical Power System,” in 2019 IEEE 8th International Conference on Advanced Power System Automation and Protection (APAP), Oct. 2019, pp. 1335–1339. doi: 10.1109/APAP47170.2019.9225126.

## False Data Injection (FDI)
[FDI Flowchart]("Goose Attacker Tool/Flowcharts/FDI - EN.png")
FDI involves an attacker deliberately injecting erroneous data or messages into the communication network *. The overarching goal of such an attack is to subvert the normal operations of the system, instigating erroneous responses, inducing system malfunctions, or in severe cases, precipitating catastrophic failures. Detection of such attacks is challenging because the attacker often has knowledge about the system and can carefully calibrate the injected data to avoid triggering alarms, making these attacks subtle and hard to identify **.

*S. Hussain, J. Hernandez Fernandez, A. K. Al-Ali, and A. Shikfa, “Vulnerabilities and countermeasures in electrical substations,” Int. J. Crit. Infrastruct. Prot., vol. 33, p. 100406, Jun. 2021, doi: 10.1016/j.ijcip.2020.100406.
**T. Nguyen, S. Wang, M. Alhazmi, M. Nazemi, A. Estebsari, and P. Dehghanian, “Electric Power Grid Resilience to Cyber Adversaries: State of the Art,” IEEE Access, vol. 8, pp. 87592–87608, 2020, doi: 10.1109/ACCESS.2020.2993233.

## Replay
[Replay Flowchart]("Goose Attacker Tool/Flowcharts/Replay - EN.png")
In a replay attack, packets are simply delayed, and not altered, causing operational errors *. A replay attack primarily undermines the process of identity verification, thereby compromising the process of authentication **. In this scenario, an attacker resends a previously received message packet to the target host with the intent to deceive the system.

*S. E. Quincozes, C. Albuquerque, D. Passos, and D. Mossé, “A survey on intrusion detection and prevention systems in digital substations,” Comput. Networks, vol. 184, no. September 2020, p. 107679, Jan. 2021, doi: 10.1016/j.comnet.2020.107679.
**F. Li, X. Yan, Y. Xie, Z. Sang, and X. Yuan, “A Review of Cyber-Attack Methods in Cyber-Physical Power System,” in 2019 IEEE 8th International Conference on Advanced Power System Automation and Protection (APAP), Oct. 2019, pp. 1335–1339. doi: 10.1109/APAP47170.2019.9225126.

## Spoofing
[Replay Flowchart]("Goose Attacker Tool/Flowcharts/Spoofing - EN.png")
Spoofing refers to the act of creating and sending falsified packets or messages that seem to come from a legitimate source in the network *. As this falsified communication carries the semblance of a legitimate publisher, it is processed as such by the subscriber devices. This deceptive interaction results in the messages coming from the legitimate publisher being ignored, leading to the omission of critical control commands that could cause power disruptions, equipment damage, and substantial safety risks in extreme scenarios.

*S. E. Quincozes, C. Albuquerque, D. Passos, and D. Mossé, “A survey on intrusion detection and prevention systems in digital substations,” Comput. Networks, vol. 184, no. September 2020, p. 107679, Jan. 2021, doi: 10.1016/j.comnet.2020.107679.
**S. Hussain, J. Hernandez Fernandez, A. K. Al-Ali, and A. Shikfa, “Vulnerabilities and countermeasures in electrical substations,” Int. J. Crit. Infrastruct. Prot., vol. 33, p. 100406, Jun. 2021, doi: 10.1016/j.ijcip.2020.100406.
