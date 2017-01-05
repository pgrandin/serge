import novaclient
import logging
import MySQLdb
import os.path
import os
import hashlib
import redis
import paramiko
import commands
import csv
import time
import requests
from jira.client import JIRA
from novaclient import client
from datetime import datetime, timedelta
from jenkinsapi.jenkins import Jenkins
import uuid
import ConfigParser
import socket
import re

# TODO : implement instance reboot

LOGGER = logging.getLogger(__name__)

class Serge(object):
    """
    Serge the Systems Engineer.
    This is a library that leverages jenkins and jira to automate the management
    of a cloud. You can manage baremetal servers, openstack nodes and instances.

    This library tries to mimic the workflow that our Systems Engineers have to
    follow by tracking work in Jira tickets and scheduling downtimes in our
    monitoring.

    It makes it easy to automate our work.
    """

    def __init__(self, zone):
        self.zone = zone
        self.Config = ConfigParser.ConfigParser()
        self.Config.read("/etc/serge.ini")
        self.nova = client.Client(
            "2",
            auth_url="http://{}.{}.{}:5000/v2.0/".format(self.Config.get('openstack', 'endpoint'), self.zone, self.Config.get('serge', 'domain')),
            username=self.Config.get('openstack', 'username'),
            api_key=self.Config.get('openstack', 'password'),
            project_id=self.Config.get('openstack', 'project'))

        self.jira = JIRA(
            {'server': self.Config.get('jira', 'server')},
            basic_auth=(self.Config.get('jira', 'email'), self.Config.get('jira', 'password'))
        )
        self.rs = redis.Redis('{}.{}.{}'.format(self.Config.get('redis', 'endpoint'), zone, self.Config.get('serge', 'domain')), db=2)
        self.create_ticket = False

    def get_infos_from_inventory(self, hostname):
        """
        Get inventory informations about a baremetal node.
        Expected format is <ipmi address>;<primary mac address>;<admin ip>;<hostname>
        """
        with open("./inventory/%s.csv" % self.zone, 'rb') as fhandle:
            csv.register_dialect('semicolon', delimiter=';')
            reader = csv.reader(fhandle, dialect='semicolon')
            inventory = list(reader)
        for node in inventory:
            if hostname == node[3]:
                return {'ipmi_ip' : node[0], 'mac_address' : node[1], 'admin_ip' : node[2]}
        return None

    def decommission(self, hostname):
        """
        Decommission a node from an Openstack cluster
        This is useful if your monitoring is based upon a dynamic list of hosts
        pulled from the nova/neutron/cinder 'service-list'
        """
        db_host = "{}.{}.{}".format(self.Config.get('openstack', 'endpoint'), self.zone, self.Config.get('serge', 'domain'))
        try:

            nova_db = MySQLdb.connect(
                host=db_host,
                port=3306, user="novaUser", passwd="novaPass", db="nova"
            )
            cursor = nova_db.cursor()
            cursor.execute("delete from compute_nodes where hypervisor_hostname like '{}%';".format(
                hostname
            ))
            cursor.execute("delete from services where host like '{}%';".format(hostname))
            nova_db.commit()
            nova_db.close()

            neutron_db = MySQLdb.connect(
                host=db_host,
                port=3306, user="neutronUser", passwd="neutronPass", db="neutron"
            )
            cursor = neutron_db.cursor()
            cursor.execute("delete from agents where host like '{}%';".format(hostname))
            cursor.execute("delete from ml2_port_bindings where host like '{}%';".format(hostname))
            neutron_db.commit()
            neutron_db.close()

            cinder_db = MySQLdb.connect(
                host=db_host,
                port=3306, user="cinderUser", passwd="cinderPass", db="cinder"
            )
            cursor = cinder_db.cursor()
            cursor.execute("delete from services where host like '{}%';".format(hostname))
            cinder_db.commit()
            cinder_db.close()
        except:
            logging.error("Decommissioning of %s.%s failed", hostname, self.zone)

    def set_downtime(self, hostname, endpoint, reason, duration=60):
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=duration)
        try:
            resp = requests.get(
                "https://{}-{}.{}/nagios/cgi-bin/cmd.cgi".format(endpoint, self.zone),
                headers={
                    "Authorization": "Basic {}".format(self.Config.get('nagios', 'token')),
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                params={
                    "cmd_typ" : "55",
                    "cmd_mod" : "2",
                    "host" : "{}".format(hostname),
                    "com_data" : reason,
                    "trigger" : "0",
                    "fixed" : "1",
                    "hours" : "0",
                    "minutes" : duration,
                    "childoptions" : "0",
                    "start_time" : "{}".format(
                        time.strftime("%m-%d-%Y %H:%M:%S", start_time.timetuple())
                    ),
                    "end_time" : "{}".format(
                        time.strftime("%m-%d-%Y %H:%M:%S", end_time.timetuple())
                    ),
                    "btnSubmit" : "Commit"
                })

            for line in resp.content.split("\n"):
                if "Message" in line:
                    logging.info(line)
        except:
            logging.error("Could not schedule downtime, moving on")

    def check_http(self, url):
        """ Performs a simple http check against a webserver or API endpoint """
        try:
            resp = requests.head(url)
            return {
                "message" : 'http check OK, result code is {}'.format(resp.status_code),
                "result" : True
            }
        except requests.ConnectionError:
            return {
                "message" : 'http check FAILED, result code is {}'.format(resp.status_code),
                "result" : False
            }

    def check_if_instance_is_healthy(self, instance, fake=False, itype=None):
        fqdn = "{}.{}.{}.public".format(instance, self.Config.get('openstack', 'tenant'), self.zone)
        try:
            socket.gethostbyname(fqdn)
        except socket.error:
            return {"message" : "I can't resolve {}".format(fqdn), "result" : False}
		# Add your own checks

        return {"message" : "I don't know how to check if {} is healthy".format(fqdn), "result" : None}

    def find_build(self, job_name, uuid):
        """
        Given a job name and a build uuid, returns informations
        about a specific Jenkins build
        """
        server = Jenkins(
            self.Config.get('jenkins', 'server'),
            username=self.Config.get('jenkins', 'username'),
            password=self.Config.get('jenkins', 'token')
        )

        job = server.get_job(job_name)
        for job_id in job.get_build_ids():
            build = job.get_build(job_id)
            parameters = build.get_actions()['parameters']

            for param in parameters:
                if param['name'] == 'serge_uuid' and \
                    param['value'] == str(uuid):
                    logging.debug("Found %s in job %s", uuid, job_id)
                    return {
                        "status" : build.get_status(),
                        "build_id" : job_id,
                        "message" : "Build URL is {}/job/{}/{}".format(self.Config.get('jenkins', 'server'), job_name, job_id)
                    }
        return None

    def run_jenkins_job(self, job_name, params):
        """
        Run a specific Jenkins job according to the parameters
        given. Returns a freshly generated UUID for the build
        that will allow to find this specific run later on.
        """
        server = Jenkins(
            self.Config.get('jenkins', 'server'),
            username=self.Config.get('jenkins', 'username'),
            password=self.Config.get('jenkins', 'token')
        )

        my_uuid = uuid.uuid4()
        params['serge_uuid'] = my_uuid
        if server.has_job(job_name):
            job_instance = server.get_job(job_name)
            logging.info("%s : %s", job_instance.python_api_url(job_name), my_uuid)
            server.build_job(job_name, params)
            return my_uuid
        else:
            logging.error("Job '%s' not found", job_name)
            return None

    def parse_job_console(self, job_name, build_id, instance):
        url = "{}/job/{}/{}/consoleText".format(self.Config.get('jenkins', 'server'), job_name, build_id)
        filename = "/tmp/jenkins-{}.txt".format(build_id)
        # TODO : use requests instead
        os.system(
            "wget --auth-no-challenge --http-user={} --http-password={} --secure-protocol=TLSv1 {} -O {} >/dev/null 2>&1".format(
                self.Config.get('jenkins', 'username'), self.Config.get('jenkins', 'token'), url, filename)
        )

        with open(filename, "r") as ins:
            for line in ins:
                if 'while (r is None or re.match(r"^OK.*", r[0]) is None):' in line:
                    return {"message" : "Found INF-5969 in job {}".format(build_id), "ticket": "INF-5969", "result": False}
                if "The certificate retrieved from the master does not match the agent's private key" in line:
                    self.clean_instance_cert(instance)
                    return {"message" : "Found cert issue in job {}".format(build_id), "result": False}
        return {"result" : None}

    def deploy(self, hostname):
        self.decommission(hostname)
        self.set_downtime(hostname, "mgmt01b", "Deploying this node")
        params = {'AVAILABILITY_ZONE': self.zone, 'os_version': 'trusty', 'hostname': hostname}
        result = self.run_jenkins_job('CM-Production-deploy', params)
        if result == None:
            return {"message" : "job 'CM-Production-deploy' cannot be started"}
        else:
            return {"message" : "Build uuid is {}".format(result), "uuid" : result}

    def notify(self, peer, message):
        hipchat_url = "https://api.hipchat.com/v2/user/{}/message?auth_token={}".format(
            peer, self.Config.get('hipchat', 'token')
        )
        resp = requests.post(hipchat_url, json={'message' : message})
        if resp.text == "":
            return None
        else:
            return resp.json()

    # Openstack administration tasks
    def get_instances_count(self, hostname):
        """ Returns the number of instances running on the given hypervisor """
        search_opts = {'host': hostname, 'all_tenants':1}
        instances_list = self.nova.servers.list(search_opts=search_opts)
        logging.info('%s instances running on %s', len(instances_list), hostname)
        return len(instances_list)

    def is_node_in_cluster(self, hostname):
        services = self.nova.services.list(hostname, 'nova-compute')
        for service in services:
            logging.info(
                "%s %s on %s : %s %s", hostname, service.binary,
                service.host, service.status, service.state)
            if service.status == "enabled" and service.state == "up":
                return True

            if service.status == "disabled":
                logging.info('Disabled with %s', service.disabled_reason)
                if service.disabled_reason != None:
                    if self.is_jira_issue_valid(service.disabled_reason):
                        logging.info(
                            "Issue %s is open, disabled reason is valid for %s",
                            service.disabled_reason, hostname
                        )
                    else:
                        title = "{}.{} is disabled with a closed ticket".format(
                            hostname, self.zone
                        )
                        body = "{} ({}). This should not happen.".format(title, service.disabled_reason)
                        self.check_jira_ticket_by_title(title=title, body=body)
                else:
                    title = "{}.{} is disabled without a reason".format(hostname, self.zone)
                    body = "{}. This should not happen.".format(title)
                    self.check_jira_ticket_by_title(title=title, body=body)
        return False

    # Jira interactions
    def is_jira_issue_valid(self, jira_id):
        """ Check if the specified Jira issue is valid """
        issue = self.jira.issue(jira_id)
        if issue:
            status = str(issue.fields.status)
            if not status in ['Open', 'In Progress', 'Reopened']:
                logging.info("%s : %s that's not valid", str(issue.key), str(issue.fields.status)
                            )
                return False
            else:
                logging.info("%s : %s that's valid", str(issue.key), str(issue.fields.status)
                            )
                return True
        else:
            return False

    def check_jira_ticket_by_title(self, title=None, body=None, umbrella=None, create_ticket=False):
        issues = self.jira.search_issues('summary ~ "{}" and status != "closed"'.format(title))
        if len(issues) > 1:
            logging.error("More than one issue found!")
            for issue in issues:
                logging.info(" - %s", issue.key)
        else:
            logging.info("%s issues found for '%s'", len(issues), title)
            if len(issues) == 1:
                issue = issues[0]

            if len(issues) == 0 or not self.is_jira_issue_valid(issue):
                if create_ticket:
                    logging.info("Issue is missing, creating it")
                    new_issue = self.jira.create_issue(
                        project='CM', summary=title, description=body,
                        issuetype={'name': 'Infrastructure Task'}
                    )
                    if umbrella != None:
                        self.jira.create_issue_link(
                            type="Blocks",
                            inwardIssue=new_issue.key,
                            outwardIssue=umbrella,
                            comment={
                                "body": "Setting '{}' as a blocker of '{}'".format(
                                    new_issue.key, umbrella
                                )
                            }
                        )
                    return new_issue.key
                else:
                    logging.warn("Ticket is missing, but I did not create it")
                    return None

            return issue.key

    def get_specs_for_hostname(self, hostname):
        specs = {}
        try:
            specs = self.rs.hgetall(hostname)
        except:
            logging.error("Fetching key %s failed, deleting entry", hostname)
            return {}
            # rs.delete(hostname)
        logging.debug("Found specs %s for node %s.%s", specs, hostname, self.zone)
        return specs

    def get_bios_checksum(self, ipmi_ip):
        cmd = "sum -i {} -u {} -p {} -c GetCurrentBiosCfgTextFile --file /tmp/{}.txt --overwrite > /dev/null".format(
            ipmi_ip,
            self.Config.get('ipmi', 'username'),
            self.Config.get('ipmi', 'password'),
            ipmi_ip)
        logging.info(cmd)
        os.system(cmd)
        if os.path.isfile("/tmp/%s.txt" % ipmi_ip):
            os.system('sed -i "s/[ \t]*$//" /tmp/{}.txt'.format(ipmi_ip))
            md5 = hashlib.md5()
            fhandle = open("/tmp/%s.txt" % ipmi_ip)
            for line in fhandle:
                md5.update(line)
            fhandle.close()
            md5_host = md5.hexdigest()
            return md5_host
        else:
            logging.error("I was unable to fetch the bios checksum for %s", ipmi_ip)
        return None

    def get_bios_config_diff(self, ipmi_ip, hostname, ignore_cache=False):
        specs = self.get_specs_for_hostname(hostname)
        md5_ref = hashlib.md5()
        if not "boardproductname" in specs or not "bios_version" in specs:
            return None
        filename = "./inventory/bios/{}-{}".format(
            specs['boardproductname'], specs['bios_version']
        )
        if os.path.isfile(filename):
            fhandle = open(filename)
            for line in fhandle:
                md5_ref.update(line)
            fhandle.close()

            if ignore_cache:
                logging.info("Clearing bios info in cache for %s.%s", hostname, self.zone)
                for rkey in self.rs.keys('bios*'):
                    self.rs.srem(rkey, hostname)

            if 'bios_config_md5' in specs and \
                not(ignore_cache) and specs['bios_config_md5'] != 'None':
                md5_host = specs['bios_config_md5']
                logging.debug("Found md5 %s in inventory", md5_host)
            else:
                md5_host = self.get_bios_checksum(ipmi_ip)
                logging.debug("Got md5 %s from get_bios_checksum()", md5_host)

                # if the md5 of the node is valid, add it to the cache
                if md5_host != None:
                    inventory = {}
                    inventory['bios_config_md5'] = md5_host
                    self.rs.hmset(hostname, inventory)
                    self.rs.expire(hostname, 660)
                else:
                    return None

            if md5_host == md5_ref.hexdigest():
                logging.debug(
                    "Reference bios config checksum for %s matches %s :)", hostname, md5_ref.hexdigest())
                return ""
            else:
                diff = (commands.getstatusoutput('diff /tmp/{}.txt ./inventory/bios/{}-{}'.format(ipmi_ip, specs['boardproductname'], specs['bios_version']))[1])
                logging.error("Reference bios config checksum for %s.%s DOES NOT MATCH %s!", hostname, self.zone, md5_ref.hexdigest())
                logging.debug(diff)
                return diff
        else:
            logging.error("Reference bios config file %s does not exist", filename)
            return False

    def safe_reboot(self, hostname):
        # TODO : check for services
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logging.info('rebooting %s.%s.%s', hostname, self.zone, self.Config.get('serge', 'domain'))
        ssh.connect(
            '{}.{}.{}'.format(hostname, self.zone, self.Config.get('serge', 'domain')),
            username='root', password=self.Config.get('baremetal', 'password'))
        stdin, stdout, stderr = ssh.exec_command("reboot; exit")

    def update_bios_config(self, hostname, reboot=False):
        inventory = self.get_infos_from_inventory(hostname)
        if inventory == None:
            logging.error("Cannot find inventory details for %s, aborting", hostname)
            return {"message" : "Cannot find inventory details for {}, aborting".format(hostname), "result" : False}
        specs = self.get_specs_for_hostname(hostname)
        if specs == None:
            logging.error("Cannot find specs for %s, aborting", hostname)
            return {"message" : "Cannot find specs for {}, aborting".format(hostname), "result" : False}
        logging.info("Clearing bios info in cache for %s", hostname)
        for rkey in self.rs.keys('bios*'):
            self.rs.srem(rkey, hostname)
        logging.info(
            "sum -i %s -u %s -p %s -c ChangeBiosCfg --file ./inventory/bios/%s-%s",
            inventory['ipmi_ip'],
            self.Config.get('ipmi', 'username'),
            self.Config.get('ipmi', 'password'),
            specs['boardproductname'],
            specs['bios_version'])
        os.system(
            "sum -i {} -u {} -p {} -c ChangeBiosCfg --file ./inventory/bios/{}-{}".format(
                inventory['ipmi_ip'],
                self.Config.get('ipmi', 'username'),
                self.Config.get('ipmi', 'password'),
                specs['boardproductname'],
                specs['bios_version'])
        )
        self.rs.delete(hostname)
        if reboot:
            self.safe_reboot(hostname)
        return {"message" : "Bios config for {}.{} updated with template {}-{}".format(hostname, self.zone, specs['boardproductname'], specs['bios_version']), "result" : True}

    def wait_for_connectivity(self, hostname):
        response = -1
        while response != 0:
            time.sleep(10)
            response = os.system("ping -c 1 {}.{}.{} > /dev/null".format(hostname, self.zone, self.Config.get('serge', 'domain')))

    def wait_for_specs(self, hostname):
        specs = None
        while specs == None or specs == {}:
            time.sleep(10)
            specs = self.get_specs_for_hostname(hostname)

    def update_bios_version(self, hostname, reboot=False):
        inventory = self.get_infos_from_inventory(hostname)
        if inventory == None:
            logging.error("Cannot find inventory details for %s, aborting", hostname)
            return False
        specs = self.get_specs_for_hostname(hostname)
        if specs == None:
            logging.error("Cannot find specs for %s, aborting", hostname)
            return False

        search_opts = {'host': hostname, 'all_tenants':1}
        list = self.nova.servers.list(search_opts=search_opts)
        if len(list) == 0:
            logging.info("No instances running on %s", hostname)
        else:
            for instance in list:
                logging.info("Found instance %s", instance.name)

        self.set_downtime(hostname, "mgmt01b", "updating BIOS version")
        logging.info("Clearing bios info in cache for %s", hostname)
        for rkey in self.rs.keys('bios*'):
            self.rs.srem(rkey, hostname)
        os.system(
            "sum -i {} -u {} -p {} -c UpdateBios --file ./inventory/bios/bin/{}".format(
                inventory['ipmi_ip'],
                self.Config.get('ipmi', 'username'),
                self.Config.get('ipmi', 'password'),
                specs['boardproductname'])
        )
        self.rs.delete(hostname)
        if reboot:
            self.safe_reboot(hostname)
            time.sleep(60)
            self.wait_for_connectivity(hostname)
            self.wait_for_specs(hostname)
            self.update_bios_config(hostname, reboot)
            time.sleep(60)
            self.wait_for_connectivity(hostname)
            self.wait_for_specs(hostname)

        return True

    def update_load_balancer(self, loadbalancer, ticket):
        logging.info("Updating load balancer %s", loadbalancer)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        fqdn = "{}.{}.{}".format(loadbalancer, self.zone, self.Config.get('serge', 'domain'))
        ssh.connect(
            fqdn,
            username='root',
            password=self.Config.get('loadbalancer', 'password'))
        stdin, stdout, stderr = ssh.exec_command("rm /opt/haproxy/etc/haproxy.cfg ; FACTER_puppet_role=baremetal::lb puppet agent --test --certname $(hostname -f) --server puppet-master04.us-east-1a.public --environment openstack --color=false")
        out = "".join(stdout.readlines())
        err = ""
        for line in stderr.readlines():
            if not "Warning: Found multiple default providers for ardeploy" in line \
              and not line.startswith('WARNING'):
                err = err + line
        if err == "":
            self.jira.add_comment(ticket, "{} updated, no errors detected".format(fqdn))
        else:
            self.jira.add_comment(ticket, "Update of {}, Stderr: {noformat}%s{noformat} " .format(fqdn, err))
        if err == "":
            return True
        return False

    def get_instances_running_on(self, hostname):
        # Check if we were given a valid hypervisor
        try:
            hosts = self.nova.hypervisors.search(hostname, True)
            if len(hosts) > 1:
                return {"message" : "More than one hypervisor matching '{} in {}', please refine your search".format(hostname, self.zone), "instances": None}
            elif len(hosts) == 0:
                return {"message" : "No hypervisor matching '{} in {}', please correct your search".format(hostname, self.zone), "instances": None}
            else:
                # Look for instances
                search_opts = {'host': hostname, 'all_tenants':1}
                list = self.nova.servers.list(search_opts=search_opts)
                if len(list) == 0:
                    return {"message" : "Nothing found on [%s]." % hostname, "instances": []}
                else:
                    out = ""
                    instances = []
                    for instance in list:
                        out = out + "{} [{}] is in state {}, hosted on {}, flavor {} and created {}, ip(s): ".format(
                            instance.name,
                            instance.id,
                            instance.status,
                            getattr(instance, 'OS-EXT-SRV-ATTR:hypervisor_hostname'),
                            instance.flavor['id'],
                            instance.created)
                        for network in instance.networks.keys():
                            for ipv4 in instance.networks[network]:
                                out = out + "%s, " % ipv4
                        out = out + "meta :"
                        for item in instance.metadata.items():
                            out = out + " %s:%s," % (item[0], item[1])
                        out = out + "\n"
                        instances.append(instance.name)
                    return {"message" : out, "instances" : instances}
        except (novaclient.exceptions.NotFound) as err:
            return {"message" : "No hypervisor matching '{} in {}', please correct your search".format(hostname, self.zone)}

    def get_instance_details(self, instance):
        search_opts = {'name': instance, 'all_tenants':1}
        list = self.nova.servers.list(search_opts=search_opts)
        if len(list) == 0:
            return {"message" : "Nothing matches this criteria"}
        else:
            out = ""
            for instance in list:
                aggregate_name = ""
                aggregates_list = self.nova.aggregates.list()
                if instance.status == "ACTIVE":
                    instance_host = getattr(instance, 'OS-EXT-SRV-ATTR:hypervisor_hostname')
                    for aggregate in aggregates_list:
                        for host in aggregate.hosts:
                            if str(host) == instance_host.split('.')[0]:
                                aggregate_name = aggregate.name
                else:
                    instance_host = "N/A"

                out = out + "{} [{}] is in state {}, hosted on {} (pool {}), flavor {} and created {}, ip(s): ".format(
                    instance.name,
                    instance.id,
                    instance.status,
                    instance_host,
                    aggregate_name,
                    instance.flavor['id'],
                    instance.created)
                for network in instance.networks.keys():
                    for ipv4 in instance.networks[network]:
                        out = out + "%s, " % ipv4
                out = out + "meta :"
                for item in instance.metadata.items():
                    out = out + " %s:%s," % (item[0], item[1])
                out = out + "\n"
                if instance.status == 'ERROR':
                    if hasattr(instance, 'fault'):
                        out = out + "\nError: {}".format(instance.fault['message'])
                    else:
                        out = out + "Instance is in error state, but I don't have more info\n"
            if len(list) > 5:
                my_uuid = uuid.uuid4()
                text_file = open("/tmp/will/%s" % my_uuid, "w")
                text_file.write("<pre>%s</pre>" % out)
                text_file.close()
                return {"message" : "More than 5 results, exported here : http://{}/lists/{}".format(self.Config.get('serge', 'fqdn'), my_uuid)}
            else:
                return {"message" : out}

    def work_on_instance(self, task, instance, title, body, issue=None):
        new_issue = self.jira.create_issue(project='OPS', summary=title, description=body, issuetype={'name': 'System Change'})
        if issue != None:
            self.jira.create_issue_link(
                type="Blocks",
                inwardIssue=new_issue.key,
                outwardIssue=issue,
                comment={
                    "body": "Setting '%s' as a blocker of maintenance '%s'" % (new_issue.key, issue),
                }
            )
        lbs = self.Config.get('openstack', 'loadbalancers')

        if instance.startswith('rtb-bidder') or \
           instance.startswith('rtb-staging-bidder') or \
           instance.startswith('rtb-adserver') or \
           instance.startswith('rtb-adevent'):
            title = "Reload load balancers configuration in {}".format(self.zone)
            body = "The instances listed in attached tickets have been cycled, we need to reload the load balancers."

            lb_ticket_id = self.check_jira_ticket_by_title(title=title, body=body, umbrella=None, create_ticket=False)
            if lb_ticket_id == None:
                lb_ticket = self.jira.create_issue(project='OPS', summary=title, description=body, issuetype={'name': 'System Change'})
                lb_ticket_id = lb_ticket.key
                lb_issue = self.jira.issue(lb_ticket_id)
                self.jira.assign_issue(lb_issue, self.Config.get('jira', 'email'))
                for load_balancer in lbs:
                    self.jira.add_comment(lb_issue, "task update lb {} in {}".format(load_balancer, self.zone))
            try:
                lb_issue
            except NameError:
                lb_issue = self.jira.issue(lb_ticket_id)
            self.jira.create_issue_link(
                type="Blocks",
                inwardIssue=new_issue.key,
                outwardIssue=lb_ticket_id,
                comment={
                    "body": "Setting '%s' as a blocker of load balancer config reload : '%s'" % (new_issue.key, lb_ticket_id),
                }
            )
        if task in ["cycle", "stop"]:
            self.jira.add_comment(new_issue, "task stop instance {}.{}.{}".format(instance, self.Config.get('openstack', 'tenant'), self.zone))
        if task in ["cycle", "start"]:
            self.jira.add_comment(new_issue, "task start instance {}.{}.{}".format(instance, self.Config.get('openstack', 'tenant'), self.zone))
        self.jira.assign_issue(new_issue, self.Config.get('jira', 'email'))
        return {"message" : "Will be done in {}/browse/{}".format(self.Config.get('jira', 'server'), new_issue.key), "result": True}

    def start_instance(self, instance, title, body):
        """ Schedule a task in a Jira ticket to start an instance """
        return self.work_on_instance("start", instance, title, body)

    def stop_instance(self, instance, title, body):
        """ Schedule a task in a Jira ticket to stop an instance """
        return self.work_on_instance("stop", instance, title, body)

    def cycle_instance(self, instance, title, body, issue=None):
        """ Schedule a task in a Jira ticket to cycle (stop then start) an instance """
        return self.work_on_instance("cycle", instance, title, body, issue)

    def check_java_process_on_instance(self, instance):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        k = paramiko.RSAKey.from_private_key_file("./ssh-keypairs/{}/{}".format(self.zone[:-1], self.Config.get('openstack', 'tenant')))

        fqdn = "{}.{}.{}".format(instance, self.Config.get('openstack', 'tenant'), self.zone)

        ssh.connect(fqdn, username='root', pkey=k, timeout=10)
        cmd = "ps -ef|grep '[j]ava'"
        stdin, stdout, stderr = ssh.exec_command(cmd)

        out = "".join(stdout.readlines())
        if out == "":
            return {"message" : "no java process found", "result": False}
        return {"message" : out, "result": True}

    def clean_instance_cert(self, instance):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        k = paramiko.RSAKey.from_private_key_file("./ssh-keypairs/puppet/admin")
        fqdn = "{}.{}.{}".format(instance, self.Config.get('openstack', 'tenant'), self.zone)
        result = {"message": "cert not found", "result":False}
        for master in self.Config.get('puppet', 'masters'):
            ssh.connect(master, username='root', pkey=k, timeout=10)
            cmd = "puppet cert clean {}".format(fqdn)
            stdin, stdout, stderr = ssh.exec_command(cmd)
            out = "".join(stdout.readlines())
            err = "".join(stderr.readlines())
            if "notice: Revoked certificate with serial" in out:
                result = {"message": "cert revoked on {}".format(master), "result" :True}
        return result
