# test

https://<APIC-IP>/api/aaaLogin.json


{
  "aaaUser": {
    "attributes": {
      "name": "admin",
      "pwd": "your_password"
    }
  }
}


https://<APIC-IP>/api/node/class/fvBD.json

Cookie: APIC-cookie=<value from login>

https://<APIC-IP>/api/node/class/fvBD.json?rsp-subtree=children&rsp-subtree-class=fvSubnet&rsp-prop-include=naming-only

https://<APIC-IP>/api/node/mo/uni/tn-<TENANT>.json?query-target=subtree&target-subtree-class=fvBD&rsp-subtree=children&rsp-subtree-class=fvSubnet&rsp-prop-include=naming-only

