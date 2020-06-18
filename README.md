# Manage Windows 7 and 2008/R2 ESU keys
As you maybe know, the end of support of Windows 7 and 2008/R2 was on January 14, 2020.

Since April, Windows Updates cannot be found by clients (managed by SCCM or an other tool), and you must purchase Extended Security Updates (ESU) from the VLSC or a CSP.
This article covers very well the topic:
https://techcommunity.microsoft.com/t5/windows-it-pro-blog/obtaining-extended-security-updates-for-eligible-windows-devices/ba-p/1167091

The activation of ESU keys (MAK keys) can be done:
- Online (endpoint must have internet access)
- with VAMT
https://docs.microsoft.com/en-us/windows/deployment/volume-activation/install-vamt
- with ActivationWs
https://github.com/dadorner-msft/ActivationWs

The script provided here allows to activate ESU when endpoint is connected to internet or by using a temporary proxy address (very useful for servers).

# Usage
Edit Configure-ESU.ps1 and edit following variables:
- $ProxyAddress
  Array of available proxies in your environment (FQDN/IP:Port)
- $ESUKeyWin7
  ESU key of Windows 7 you have purchased
- $ESUKeyWin2k8
  ESU key of Windows 2008/R2 you have purchased

Personnally, I use SCCM with a package containing the PowerShell script and a Task Sequence for running the script with an administrator account (**a proxy cannot be configured on a SYSTEM context**).
