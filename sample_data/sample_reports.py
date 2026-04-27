"""
Sample inventory XML report for testing.
"""

sample_inventory_xml = """<?xml version="1.0" encoding="UTF-8"?>
<inventory>
    <hosts>
        <Host>
            <ip>192.168.1.10</ip>
            <hostname>DC01</hostname>
            <os>Windows Server 2019 Datacenter</os>
            <architecture>x64</architecture>
            <domainRole>Domain Controller</domainRole>
            <macAddress>00:1A:2B:3C:4D:5E</macAddress>
            
            <networkInterfaces>
                <interface>
                    <name>Ethernet0</name>
                    <ip>192.168.1.10</ip>
                    <mask>255.255.255.0</mask>
                    <gateway>192.168.1.1</gateway>
                    <dns>192.168.1.10, 192.168.1.11</dns>
                    <mac>00:1A:2B:3C:4D:5E</mac>
                </interface>
            </networkInterfaces>
            
            <users>
                <user>
                    <name>Administrator</name>
                    <type>Local</type>
                    <enabled>true</enabled>
                    <lastLogin>2024-01-15 08:30:00</lastLogin>
                </user>
                <user>
                    <name>Domain Admin</name>
                    <type>Domain</type>
                    <enabled>true</enabled>
                    <lastLogin>2024-01-15 09:15:00</lastLogin>
                </user>
            </users>
            
            <services>
                <service>
                    <name>Active Directory Domain Services</name>
                    <status>Running</status>
                    <startup>Automatic</startup>
                    <path>C:\Windows\System32\lsass.exe</path>
                </service>
                <service>
                    <name>DNS Server</name>
                    <status>Running</status>
                    <startup>Automatic</startup>
                    <path>C:\Windows\System32\dns.exe</path>
                </service>
            </services>
            
            <installedSoftware>
                <software>
                    <name>Microsoft Office 2019</name>
                    <version>16.0.10330.20332</version>
                    <date>2023-06-15</date>
                    <vendor>Microsoft Corporation</vendor>
                </software>
                <software>
                    <name>7-Zip 21.07</name>
                    <version>21.07</version>
                    <date>2023-08-20</date>
                    <vendor>Igor Pavlov</vendor>
                </software>
            </installedSoftware>
            
            <updates>
                <update>
                    <id>KB5034441</id>
                    <name>2024-01 Security Update</name>
                    <date>2024-01-09</date>
                </update>
                <update>
                    <id>KB5034203</id>
                    <name>2024-01 Servicing Stack Update</name>
                    <date>2024-01-03</date>
                </update>
            </updates>
            
            <securityPolicies>
                <policy>
                    <name>Password Complexity</name>
                    <value>Enabled</value>
                    <enabled>true</enabled>
                </policy>
                <policy>
                    <name>Account Lockout Threshold</name>
                    <value>5</value>
                    <enabled>true</enabled>
                </policy>
            </securityPolicies>
        </Host>
        
        <Host>
            <ip>192.168.1.20</ip>
            <hostname>APP01</hostname>
            <os>Windows Server 2022 Standard</os>
            <architecture>x64</architecture>
            <domainRole>Member Server</domainRole>
            <macAddress>00:1A:2B:3C:4D:5F</macAddress>
            
            <networkInterfaces>
                <interface>
                    <name>Ethernet0</name>
                    <ip>192.168.1.20</ip>
                    <mask>255.255.255.0</mask>
                    <gateway>192.168.1.1</gateway>
                    <dns>192.168.1.10</dns>
                    <mac>00:1A:2B:3C:4D:5F</mac>
                </interface>
            </networkInterfaces>
            
            <services>
                <service>
                    <name>World Wide Web Publishing Service</name>
                    <status>Running</status>
                    <startup>Automatic</startup>
                    <path>C:\Windows\System32\inetsrv\w3wp.exe</path>
                </service>
            </services>
            
            <installedSoftware>
                <software>
                    <name>Microsoft SQL Server 2019</name>
                    <version>15.0.2000.5</version>
                    <date>2023-09-10</date>
                    <vendor>Microsoft Corporation</vendor>
                </software>
            </installedSoftware>
        </Host>
    </hosts>
</inventory>
"""

sample_pentest_xml = """<?xml version="1.0" encoding="UTF-8"?>
<scanResults>
    <metadata>
        <scanType>Network Pentest</scanType>
        <profile>Full Scan</profile>
        <startTime>2024-01-15 10:00:00</startTime>
        <endTime>2024-01-15 12:30:00</endTime>
        <scannerVersion>RedCheck 3.5</scannerVersion>
    </metadata>
    
    <hosts>
        <host>
            <ip>192.168.1.10</ip>
            <hostname>dc01.corp.local</hostname>
            
            <ports>
                <port>
                    <portId>53</portId>
                    <protocol>tcp</protocol>
                    <state>open</state>
                </port>
                <port>
                    <portId>88</portId>
                    <protocol>tcp</protocol>
                    <state>open</state>
                </port>
                <port>
                    <portId>135</portId>
                    <protocol>tcp</protocol>
                    <state>open</state>
                </port>
                <port>
                    <portId>389</portId>
                    <protocol>tcp</protocol>
                    <state>open</state>
                </port>
                <port>
                    <portId>445</portId>
                    <protocol>tcp</protocol>
                    <state>open</state>
                </port>
            </ports>
            
            <services>
                <service>
                    <name>domain</name>
                    <product>BIND</product>
                    <version>9.11.4</version>
                    <port>53</port>
                </service>
                <service>
                    <name>kerberos</name>
                    <product>Microsoft Kerberos</product>
                    <version>6.1</version>
                    <port>88</port>
                </service>
                <service>
                    <name>ldap</name>
                    <product>Microsoft LDAP</product>
                    <version>6.0</version>
                    <port>389</port>
                </service>
                <service>
                    <name>microsoft-ds</name>
                    <product>Microsoft Windows SMB</product>
                    <version>10.0</version>
                    <port>445</port>
                    <signatureRequired>true</signatureRequired>
                    <signatureEnabled>true</signatureEnabled>
                </service>
            </services>
            
            <banners>
                <banner>Microsoft Windows [Version 10.0.17763.5202]</banner>
            </banners>
            
            <smb>
                <signatureRequired>true</signatureRequired>
                <signatureEnabled>true</signatureEnabled>
                <domain>CORP</domain>
                <osVersion>Windows Server 2019 Datacenter 17763</osVersion>
                <serverType>NT LM 0.12</serverType>
                <lanmanVersion>LanMan 2.1</lanmanVersion>
                <ntlmVersion>NTLMv2</ntlmVersion>
            </smb>
        </host>
        
        <host>
            <ip>192.168.1.20</ip>
            <hostname>app01.corp.local</hostname>
            
            <ports>
                <port>
                    <portId>80</portId>
                    <protocol>tcp</protocol>
                    <state>open</state>
                </port>
                <port>
                    <portId>443</portId>
                    <protocol>tcp</protocol>
                    <state>open</state>
                </port>
                <port>
                    <portId>1433</portId>
                    <protocol>tcp</protocol>
                    <state>open</state>
                </port>
                <port>
                    <portId>3389</portId>
                    <protocol>tcp</protocol>
                    <state>open</state>
                </port>
            </ports>
            
            <services>
                <service>
                    <name>http</name>
                    <product>Microsoft IIS httpd</product>
                    <version>10.0</version>
                    <port>80</port>
                </service>
                <service>
                    <name>https</name>
                    <product>Microsoft IIS httpd</product>
                    <version>10.0</version>
                    <port>443</port>
                </service>
                <service>
                    <name>ms-sql-s</name>
                    <product>Microsoft SQL Server 2019</product>
                    <version>15.00.2000</version>
                    <port>1433</port>
                </service>
                <service>
                    <name>ms-wbt-server</name>
                    <product>Microsoft Terminal Services</product>
                    <version>10.0</version>
                    <port>3389</port>
                </service>
            </services>
            
            <smb>
                <signatureRequired>false</signatureRequired>
                <signatureEnabled>false</signatureEnabled>
                <domain>WORKGROUP</domain>
            </smb>
        </host>
    </hosts>
</scanResults>
"""

sample_vulnerability_xml = """<?xml version="1.0" encoding="UTF-8"?>
<vulnerabilityScan>
    <metadata>
        <scanType>Vulnerability Assessment</scanType>
        <profile>Critical Infrastructure</profile>
        <targetIp>192.168.1.0/24</targetIp>
        <startTime>2024-01-15 14:00:00</startTime>
        <endTime>2024-01-15 16:45:00</endTime>
        <scannerVersion>RedCheck VA 4.2</scannerVersion>
        <parameters>--aggressive --exploit-check</parameters>
    </metadata>
    
    <vulnerabilities>
        <vulnerability>
            <id>VULN-2024-0001</id>
            <cve>CVE-2024-21351</cve>
            <name>Windows NTLM Elevation of Privilege</name>
            <cvss>9.8</cvss>
            <severity>Critical</severity>
            <exploitAvailable>true</exploitAvailable>
            <exploitationStatus>Active in the wild</exploitationStatus>
            <targetIp>192.168.1.10</targetIp>
            <targetPort>445</targetPort>
            <description>NTLM authentication bypass vulnerability allows remote attackers to elevate privileges.</description>
            <remediation>Install KB5034441 or later security update. Disable NTLM if not required.</remediation>
        </vulnerability>
        
        <vulnerability>
            <id>VULN-2024-0002</id>
            <cve>CVE-2024-21410</cve>
            <name>Microsoft Outlook Remote Code Execution</name>
            <cvss>9.0</cvss>
            <severity>Critical</severity>
            <exploitAvailable>true</exploitAvailable>
            <exploitationStatus>PoC available</exploitationStatus>
            <targetIp>192.168.1.20</targetIp>
            <targetPort>0</targetPort>
            <description>Specially crafted email messages can trigger RCE when previewed in Outlook.</description>
            <remediation>Apply latest Outlook security updates. Consider disabling preview pane.</remediation>
        </vulnerability>
        
        <vulnerability>
            <id>VULN-2024-0003</id>
            <cve>CVE-2023-36884</cve>
            <name>Microsoft Office and Windows HTML Remote Code Execution</name>
            <cvss>8.3</cvss>
            <severity>High</severity>
            <exploitAvailable>true</exploitAvailable>
            <exploitationStatus>Exploited in targeted attacks</exploitationStatus>
            <targetIp>192.168.1.10</targetIp>
            <targetPort>0</targetPort>
            <description>Office and Windows HTML content processing vulnerabilities allow RCE.</description>
            <remediation>Apply all available Microsoft security updates. Use Protected View for Office.</remediation>
        </vulnerability>
        
        <vulnerability>
            <id>VULN-2024-0004</id>
            <cve>CVE-2024-21358</cve>
            <name>Windows SmartScreen Security Feature Bypass</name>
            <cvss>7.5</cvss>
            <severity>High</severity>
            <exploitAvailable>false</exploitAvailable>
            <exploitationStatus>Not known to be exploited</exploitationStatus>
            <targetIp>192.168.1.20</targetIp>
            <targetPort>0</targetPort>
            <description>SmartScreen can be bypassed by specially crafted files.</description>
            <remediation>Apply Windows security updates. Enable additional application controls.</remediation>
        </vulnerability>
        
        <vulnerability>
            <id>VULN-2024-0005</id>
            <cve>CVE-2024-21360</cve>
            <name>Windows Kernel Elevation of Privilege</name>
            <cvss>7.8</cvss>
            <severity>High</severity>
            <exploitAvailable>false</exploitAvailable>
            <exploitationStatus>Not known to be exploited</exploitationStatus>
            <targetIp>192.168.1.10</targetIp>
            <targetPort>0</targetPort>
            <description>Kernel vulnerability allows local users to gain SYSTEM privileges.</description>
            <remediation>Apply latest Windows cumulative update.</remediation>
        </vulnerability>
        
        <vulnerability>
            <id>VULN-2024-0006</id>
            <cve>CVE-2023-38146</cve>
            <name>DNS Server Vulnerability</name>
            <cvss>5.3</cvss>
            <severity>Medium</severity>
            <exploitAvailable>false</exploitAvailable>
            <exploitationStatus>Not known to be exploited</exploitationStatus>
            <targetIp>192.168.1.10</targetIp>
            <targetPort>53</targetPort>
            <description>DNS server may respond incorrectly to certain queries.</description>
            <remediation>Update DNS server software to latest version.</remediation>
        </vulnerability>
        
        <vulnerability>
            <id>VULN-2024-0007</id>
            <name>SMB Signing Not Required</name>
            <cvss>5.0</cvss>
            <severity>Medium</severity>
            <exploitAvailable>false</exploitAvailable>
            <exploitationStatus>N/A</exploitationStatus>
            <targetIp>192.168.1.20</targetIp>
            <targetPort>445</targetPort>
            <description>SMB signing is not required on this host, allowing potential MITM attacks.</description>
            <remediation>Enable SMB signing requirement via Group Policy.</remediation>
        </vulnerability>
        
        <vulnerability>
            <id>VULN-2024-0008</id>
            <name>RDP Network Level Authentication Not Enforced</name>
            <cvss>4.3</cvss>
            <severity>Medium</severity>
            <exploitAvailable>false</exploitAvailable>
            <exploitationStatus>N/A</exploitationStatus>
            <targetIp>192.168.1.20</targetIp>
            <targetPort>3389</targetPort>
            <description>NLA is not enforced for RDP connections.</description>
            <remediation>Enable NLA for RDP in system properties.</remediation>
        </vulnerability>
    </vulnerabilities>
</vulnerabilityScan>
"""
