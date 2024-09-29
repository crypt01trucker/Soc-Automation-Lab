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
2. **Update Wazuh manager server**:
   ```bash
   sudo apt-get update && apt-get upgrade -y
   ```
3. **Configure Firewall in could portal**: Open ports 1514 and 1515 (for Wazuh endpoint agents), and open port 55000 (for integration with Shuffle).
4. **Configure Firewall in Wazuh manger server**: Open ports 1514, 1515, and 55000 for Wazuh agent and Shuffle integration.
    ```bash
    ufw allow 1514/tcp
    ufw allow 1514/udp
    ufw allow 1515/tcp
    ufw allow 1515/udp
    ufw allow 55000/tcp
    ufw allow 55000/udp
    ```
5. **Install Wazuh Manager**: Note: Always use the latest command from the Wazuh documentation to ensure compatibility.
    ```bash
    curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
    ```
6. **Save Credentials**: After installation, save the credentials displayed for the Wazuh web portal admin credentials in your password manager. If you forget, you can retrieve them using:
    ```bash
    sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
    ```
7. **Access the Wazuh Dashboard**: Sign in to the Wazuh Manager using its public IP address. Navigate to the “Deploy new agent” and select the operating system, which in this case is Linux. Add the public IP address of the Wazuh manager and copy the command to install the Wazuh endpoint agent. Save this command for later use when we create the victim Ubuntu VM.

#### 3. Create Victim Ubuntu VM
1. **Update System**:
    ```bash
    sudo apt-get update && apt-get upgrade -y
    ```
3. **Install Wazuh Agent**: Use the command copied from the Wazuh dashboard earlier:
    ```bash
    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_amd64.deb && sudo WAZUH_MANAGER='WAZUH-PUBLIC-IP' dpkg -i ./wazuh-agent_4.9.0-1_amd64.deb
    ```
4. **Start Wazuh Agent**: Use these commands to start and check the status of the Wazuh agent.
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent
    sudo systemctl status wazuh-agent
    ```
5. **Verify Agent**: Go back to the Wazuh web portal and confirm that the agent appears in the Wazuh dashboard.

#### 1. Configure Wazuh Manager to log all events
- **Edit Configuration**:
    ```bash
    sudo nano /var/ossec/etc/ossec.conf
    ```
    Enable logging by setting both `logall` and `logall_json` to `yes`.

#### 2. Set Up Shuffle
Now let's sign up for Shuffle at shuffler.io.
1. **Create Workflow**: After signing in, click on “New Workflow.” Give it a name, something like “SOC Automation,” and then click “Save.”
2. **Add Webhook Trigger**: 
   - Click on “Triggers” at the bottom left corner of your screen, select “Webhook,” and drag it into the middle of your workflow.
   - Click on the "Webhook app" and rename it Wazuh-Alerts.
3. **Configure the Change Me App**
   - Click on the Change Me app.
   - Change the name to Repeater.
   - In the Call box, delete "Hello World" text. Next click on the plus icon and select on "Execution Argument".
   - Save the workflow.
4. **Add Shuffle Integration**: Add the integration tag into the Wazuh configuration file.
   - Navigate back to the Webhook app "Wazuh-Alerts" and copy the URL. Then, paste this URL into the Shuffle integration tag within the Wazuh manager configuration file.
    ```xml
    <integration>
      <name>shuffle</name>
      <hook_url>http://<YOUR_SHUFFLE_URL></hook_url>
      <level>5</level>
      <alert_format>json</alert_format>
    </integration>
    ```
    After editing the configuration file, restart the Wazuh Manager and check its status:
    ```bash
    sudo systemctl restart wazuh-manager.service
    sudo systemctl status wazuh-manager.service
    ```
5. **Testing Wazuh Alerts Forwarding to Shuffle**
   - Return to Shuffle, select the Webhook app ‘Wazuh-Alerts’, and click the "Start" button.
   - You should now see a lot of alerts coming from the victim VM because the SSH port is open.
#### 3. Filter Specific Alerts
1. **Identify Failed SSH Attempts**: In Shuffle, look for alerts with "User Login Failed".
   - For this lab we will chose rule id "5503" "User Login Failed".
2. **Modify Integration**: Replace `<level>5</level>` with `<rule_id>5503</rule_id>` to only forward alerts with "User Login Failed":
    ```xml
    <integration>
      <name>shuffle</name>
      <hook_url>http://<YOUR_SHUFFLE_URL>/api/v1/hooks/<HOOK_ID></hook_url>
      <rule_id>5503</rule_id>
      <alert_format>json</alert_format>
    </integration>
    ```

### 4. Configuring HTTP App for Wazuh API Authentication

- Add the HTTP app and drag it into your workflow.
- Rename it to "API_Auth".
- Change the find action to `curl` and input:

    ```bash
    curl -u <username>:<password> -k -X GET "https://<YOUR_WAZUH_MANAGER_IP>:55000/security/user/authenticate?raw=true"
    ```
- Use this commmand in your wazuh manager to find the API user password:
    ```bach
    sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
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
