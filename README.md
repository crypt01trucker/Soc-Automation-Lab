# Soc-Automation-Lab

# SOC Automation: Integrating Wazuh Alerts with Shuffle - A Hands-On Guide

## Introduction
Welcome to this hands-on guide designed for SOC analysts looking to gain practical experience in Security Operations Center (SOC) automation. In this guide, we’ll take you through the step-by-step process of automating Wazuh alerts using Shuffle. By the end, you’ll have valuable skills to enhance your SOC capabilities, including setting up an automated workflow to handle unsuccessful SSH login attempts on an Ubuntu server.

## Objectives
Setting up an automated SOC environment. Configure Wazuh for threat detection and Shuffle for workflow automation, focusing on automatically blocking IP addresses attempting unauthorized SSH logins.

## Prerequisites
- **Password Manager**: You'll be creating multiple accounts and VMs, so a password manager is highly recommended.
- **Cloud Account**: Choose a cloud provider like AWS, GCP, Digital Ocean, or Vultr (whichever offers a free tier for this exercise)
- **Two Ubuntu VMs**: 
  1. Wazuh Manager 
  2. Victim Ubuntu VM (for SSH attack simulation)

### Setting Up the Environment

##### 1. Create a Virtual Network
- Create a virtual network in your cloud platform.
- Allow only your public IP in the firewall to secure access.

##### 2. Create Wazuh Manager VM
1. **Choose Ubuntu 22.04**: For the Wazuh Manager.
2. **Configure Firewall**: Open ports 1514, 1515, and 55000 for Wazuh agent and Shuffle integration.
    ```bash
    sudo apt-get update && apt-get upgrade -y
    ufw allow 1514/tcp
    ufw allow 1514/udp
    ufw allow 1515/tcp
    ufw allow 1515/udp
    ufw allow 55000/tcp
    ufw allow 55000/udp
    ```
3. **Install Wazuh Manager**:
    ```bash
    curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
    ```
4. **Save Credentials**: After installation, save the credentials for the Wazuh dashboard.
    ```bash
    sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
    ```
5. **Access the Wazuh Dashboard**: Sign in using the Wazuh Manager’s public IP and add an agent from the dashboard.

#### 3. Create Victim Ubuntu VM
1. **Update System**:
    ```bash
    sudo apt-get update && apt-get upgrade -y
    ```
2. **Open SSH Port**: In your cloud provider’s portal.
3. **Install Wazuh Agent**: Use the command copied from the Wazuh dashboard (Agent installation):
    ```bash
    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_amd64.deb
    sudo dpkg -i ./wazuh-agent_4.9.0-1_amd64.deb
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent
    sudo systemctl status wazuh-agent
    ```
4. **Verify Agent**: Confirm the agent appears in the Wazuh dashboard.

### Part 2: Automating Responses with Wazuh and Shuffle

#### 1. Configure Wazuh Manager
- **Edit Configuration**:
    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```
    Enable logging by setting `logall` and `logall_json` to `yes`.

#### 2. Set Up Shuffle Workflow
1. **Create Workflow**: Name it “SOC Automation”.
2. **Add Webhook Trigger**: 
   - Go to Shuffle, add a webhook, and copy its URL.
3. **Modify Wazuh Integration**: Add the webhook URL to the Wazuh configuration file.
    ```xml
    <integration>
      <name>shuffle</name>
      <hook_url>http://<YOUR_SHUFFLE_URL>/api/v1/hooks/<HOOK_ID></hook_url>
      <level>3</level>
      <alert_format>json</alert_format>
    </integration>
    ```
    After editing, restart Wazuh Manager:
    ```bash
    sudo systemctl restart wazuh-manager.service
    sudo systemctl status wazuh-manager.service
    ```

#### 3. Filter Specific Alerts
1. **Identify Failed SSH Attempts**: In the Wazuh dashboard, look for alerts with `rule_id: 5503`.
2. **Modify Integration**: Replace `<level>` with `<rule_id>5503</rule_id>` to forward only SSH failure alerts:
    ```xml
    <integration>
      <name>shuffle</name>
      <hook_url>http://<YOUR_SHUFFLE_URL>/api/v1/hooks/<HOOK_ID></hook_url>
      <rule_id>5503</rule_id>
      <alert_format>json</alert_format>
    </integration>
    ```

#### 4. Set Up Active Response in Wazuh
1. **Configure Active Response**:
    - Modify the active-response section in `/var/ossec/etc/ossec.conf`:
    ```xml
    <active-response>
      <command>firewall-drop</command>
      <location>local</location>
      <level>5</level>
      <timeout>no</timeout>
    </active-response>
    ```
    Restart Wazuh Manager:
    ```bash
    sudo systemctl restart wazuh-manager.service
    ```

#### 5. Build the Shuffle Workflow
1. **Add HTTP App**: 
   - Use it for Wazuh API authentication with the following command:
    ```bash
    curl -u <user>:<password> -k -X GET "https://localhost:55000/security/user/authenticate?raw=true"
    ```
2. **Add Wazuh App**:
    - For active response, create the following JSON body to drop the IP of failed SSH attempts:
    ```json
    {
      "alert": {
        "data": {
          "srcip": "$exec.all_fields.data.srcip"
        }
      },
      "command": "firewall-drop0"
    }
    ```

3. **Finalize Workflow**:
    - The workflow should ask a SOC analyst whether to block an IP after receiving a failed SSH alert. If the analyst confirms, Wazuh will block the IP.

### Screenshots
- Add screenshots of your cloud environment setup, Wazuh Manager installation, agent configuration, and Shuffle workflow to enhance the documentation.

### Verification
- Verify that failed SSH attempts trigger the workflow, and confirm that the IP is blocked by checking `iptables` on the victim VM:
    ```bash
    sudo iptables --list
    ```

### License
This project is licensed under the MIT License.
