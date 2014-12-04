#!/usr/bin/python

import os
import sys
import threading
from threading import Thread
import re
import time
import subprocess
import Queue

#################################
#								#
#			Variables			#
#								#
#################################

# Lists and Dictionary
parallel_ssh_results = {}
results_list = []
output_list = []
no_results = []
new_host_list = []

# Inputs
host_list = open(sys.argv[1], 'r').readlines()
output = open(sys.argv[2], 'a')

# SSH Key Info
KEY='id_rsa'  
KEYFILE = None
POSSIBLE_KEY_PATHS = [ os.path.expanduser('~')+'/.ssh/'+KEY ]

# Regex's
regex_192 = re.compile(r'^192')
regex_ip = re.compile(r"^(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])$")

# Commands to execute on remote hosts
command_list = ['/sbin/ifconfig ; /bin/netstat -rn']

# Queue
queue = Queue.Queue()



##################################################
#                                                #
#               Functions                        #
#                                                #
##################################################

# Function for parsing and formatting results
def formatter(results_list):
	print 'Running formatter...'
	print 'Number of results = %s' % len(results_list.keys())
	for host in results_list:
		eth_output = results_list[host].split('Kernel')[0]
		gw_output = results_list[host].split('Kernel')[1]
		
		# Determine if eth0 or eth1 is a routeable IP Address
		for i in range(1,2):
			eth_check = eth_output.split('eth')[i].split('\n')[1].strip().split(' ')[1].split(':')[1]
			cidr_check = eth_output.split('eth')[i].split('\n')[1].strip().split(' ')[5].split(':')[1]
			if regex_ip.findall(eth_check):
				if not regex_192.findall(eth_check):
                                        addr = eth_check
					cidr = cidr_check
					
		# Convert standard subnet mask into CIDR notation
		if '255.255.255.0' in cidr:
			new_cidr = '/24'
		elif '255.255.255.128' in cidr:
			new_cidr = '/25'
		elif '255.255.255.192' in cidr:
			new_cidr = '/26'
		elif '255.255.255.224' in cidr:
			new_cidr = '/27'
		elif '255.255.255.240' in cidr:
			new_cidr = '/28'
		elif '255.255.255.248' in cidr:
			new_cidr = '/29'
		elif '255.255.255.252' in cidr:
			new_cidr = '/30'
		else:
			new_cidr = 'Unknown CIDR'

		# Find a valid gateway address
		gw_output = gw_output.split('\n')[1:]
		for line in gw_output:
			col = line.split()[1]
			if regex_ip.findall(col) and '0.0.0.0' not in col:
			    gwy = col
			    break
  
		print '%s = %s%s %s' % (host, addr, new_cidr, gwy)
		add = (addr, new_cidr, gwy)
		output_list.append(add)


# Function to SSH into a host and execute a command
def ssh(host, command_list, fork=False, parallel=True, user="root", debug=False):
	"""Run a command via ssh on a given host.  Set fork=True if the command
	should fork."""
	global __parallel_ssh_results
	global __results
	args = ["ssh", 
			"-o", "StrictHostKeyChecking=no", 
			"-o", "ConnectTimeout=15",
			]
	if KEYFILE:
		args.extend(["-i", KEYFILE])
	
	args.append(host)
	
	for command in command_list:
		if fork:
			command += " </dev/null >/dev/null 2>&1 &"
		
		args.append(command)
		
		if debug:
			print 'ssh %s %s' % (host, command)
	
		p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		results = p.communicate()[0]
			   
		if results:
			lock = threading.Lock()
			lock.acquire()	
			parallel_ssh_results[host] = results
			lock.release()
		else:
			print 'No results for %s' % host
			no_results.append(host)
			
		if debug:
			print host
			print '\t', 'stdout:', results_list[0]
		
	print '%s complete' % host
	queue.task_done()
	
	
# Function to use the above SSH function for multi-threading
def parallel_ssh(command, print_output=True, fork=False, timeout=True, progressive_results_dissection=True):
	"""Use python threads to run an ssh command on a number of servers.
	Set fork=True if the command should fork and run in the background on
	the hosts.  Returns a dict of {hostname:result} for each host."""
	global parallel_ssh_results 
	print 'Number of hosts in queue = %s' % queue.qsize()
	for i in range(queue.qsize()):
		host = queue.get()
		t = Thread(target=ssh, args=([host, command, fork, True]))
		t.setDaemon(True)
		t.start()
	
	queue.join()
	

# Function to find and print out what hosts timed out
def detect_timeouts(parallel_ssh_results):
	"""Returns a list of hosts which timed out (ssh reports failure via
	timeout, this just parses the results and tells us which hosts failed in
	this fashion)."""
	timeouts = []
	for host in parallel_ssh_results:
		stderr = parallel_ssh_results[host][1]
		if re.search("ssh: connect to host %s port 22: Connection timed out" % host, stderr):
			print host, "timed out"
			timeouts.append(host)
	return timeouts
	

# Function to find out if the proper ssh keys are in place
def find_keys():
	for path in POSSIBLE_KEY_PATHS:
		if os.path.exists(path):
			# silence if this works fine; we print a message otherwise
			#print 'found keyfile %s' % path
			KEYFILE = path
			# now make sure the permissions are correct if we don't do this then
			# ssh will refuse to use the key but we must be careful to check that
			# it's not already done and/or we have perms to do so otherwise we spam
			# logfiles when running as an unprivelaged user
			 
			if os.access(KEYFILE, os.W_OK | os.R_OK) and not oct(os.stat(KEYFILE)[stat.ST_MODE] & 0777) == '0600':
				if raw_input('change permissions of %s to 600 so it can be used by ssh via ssh.py ? (y/n) ' % KEYFILE) == 'y':
					os.system('chmod 600 %s' % KEYFILE)
				else:
					print 'did not change permissions, per user request'


	if KEYFILE is None:  # we haven't found a key anywhere
		print 'Could not find key for use as ssh key'
		print 'tried: %s' % ' '.join(POSSIBLE_KEY_PATHS)
		

##############################################
#                                            #
#                 Main                       #
#                                            #
##############################################

def main():
	find_keys()
	
	# Ensure given host list is in proper format
	for item in host_list:
		new_host = item.strip()
		new_host = new_host.rstrip('\n')
		if new_host:
			queue.put(new_host)

	# Call functions
	parallel_ssh(command_list)	
	formatter(parallel_ssh_results)
	detect_timeouts(parallel_ssh_results)
	
	# Write results to output file
	for tuple in output_list:
		output.write('%s%s %s\n' % (tuple[0], tuple[1], tuple[2]))
	output.close()
		
if __name__ == '__main__':
    main()
