/*
 * ngrt4nd.cpp
# ------------------------------------------------------------------------ #
# Copyright (c) 2010-2012 Rodrigue Chakode (rodrigue.chakode@ngrt4n.com)   #
# Last Update : 24-05-2012                                                 #
#                                                                          #
# This file is part of NGRT4N (http://ngrt4n.com).                         #
#                                                                          #
# NGRT4N is free software: you can redistribute it and/or modify           #
# it under the terms of the GNU General Public License as published by     #
# the Free Software Foundation, either version 3 of the License, or        #
# (at your option) any later version.                                      #
#                                                                          #
# NGRT4N is distributed in the hope that it will be useful,                #
# but WITHOUT ANY WARRANTY; without even the implied warranty of           #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
# GNU General Public License for more details.                             #
#                                                                          #
# You should have received a copy of the GNU General Public License        #
# along with NGRT4N.  If not, see <http://www.gnu.org/licenses/>.          #
#--------------------------------------------------------------------------#
 */

#include "config.h"
#include "core/ns.hpp"
#include "core/MonitorBroker.hpp"
#include "core/ZmqSocket.hpp"
#include <zmq.h>
#include <cassert>
#include <stdexcept>
#include <iostream>
#include <unistd.h>
#include <crypt.h>
#include <sstream>
#include <fstream>
#include <libgen.h>
#include <iostream>
#include <stdio.h>
#include <memory>


std::string packageName = PACKAGE_NAME;
std::string packageVersion = PACKAGE_VERSION;
std::string packageUrl = PACKAGE_URL;
std::string statusFile = "/usr/local/nagios/var/status.dat";
std::string unixcatPath = "unixcat";
std::string livestatusSocket = "/var/lib/nagios/rw/live";
std::string progName = "";
std::string authChain= "";

/**
 * @brief Redirect a message to Livestatus socket and get output
 * @param command The command
 * @param msg The standard output/error message
 * @return nothing
 */
void
redirectRequestToLivestatus(std::string input, std::string& output)
{
  const int BUFFER_UNIT_SIZE = 1024;
  const int RESULT_BUFFER_SIZE = 2 * 1024 * 1024;

  char command[BUFFER_UNIT_SIZE];
  sprintf(command, "echo %s | %s %s", input.c_str(), unixcatPath.c_str(), livestatusSocket.c_str());

  FILE* pipe = popen(command, "r");
  char resultBuffer[RESULT_BUFFER_SIZE];
  if (! pipe) {
    sprintf(resultBuffer, "{\"return_code\" : \"-1\", \"message\" : \"Error running command %s\"}", command);
  } else {
    char readBuffer[BUFFER_UNIT_SIZE];
    while(! feof(pipe)) {
      if(fgets(readBuffer, BUFFER_UNIT_SIZE, pipe) != NULL) {
        output += readBuffer;
      }
    }
    sprintf(resultBuffer, "{\"return_code\" : \"0\", \"message\" : \"%s\"}", output.c_str());
    pclose(pipe);
  }
  output = std::string(resultBuffer);
}

/**
 * @brief Print help
 * @return
 */
std::string help() {
  std::ostringstream msg("SYNOPSIS\n"
                         "	" + progName +" [OPTIONS]\n"
                         "\n"
                         "DESCRIPTION\n"
                         "   Service to retrieve status data from a Nagios-like monitoting system.\n"
                         "   By default the service relies on Nagios status.dat to serve monitoring.\n"
                         "   But altervatively, it can also work as a network-broker to enable\n"
                         "   remote access to Livestatus over network."
                         "\n"
                         "OPTIONS\n"
                         "	-p\n"
                         "	 Set the listening port. Default is 1983.\n"
                         "	-l\n"
                         "	 Start the service as Livestatus broker.The default mode relies on status.dat\n"
                         "	-c FILE\n"
                         "	 If using Livestatus mode. Set the path to the Nagios status file. Default is " + statusFile + ".\n"
                         "	-D\n"
                         "	 Run the program in foreground mode.\n"
                         "	-P\n"
                         "	 Change the authentication token.\n"
                         "	-T\n"
                         "	 Print the authentication token.\n"
                         "	-s\n"
                         "	 Set the path to Livestatus socket. Default is "+livestatusSocket+"\n"
                         "	-u\n"
                         "	 Set the path to MK Livestatus unixcat utility. Find in PATH by default\n"
                         "	-v\n"
                         "	 Print the version and copyright information.\n"
                         "	-h\n"
                         "	 Print this help.\n");
  return msg.str();
}

/**
 * @brief Print version info and copyright info
 * @param progName The name of the program
 * @return
 */
std::string getVersionMsg(const std::string& progName)
{
  char msg[1024];
  sprintf(msg, "> %s %s"
          "\n>> Copyright (c) 2010-2014 RealOpInsight Labs. All rights reserved"
          "\n>> Licensed under GNU GPLv3 <http://gnu.org/licenses/gpl.html>"
          "\n>> For bug report, see: <%s>",
          progName.c_str(), packageVersion.c_str(), packageUrl.c_str());
  return std::string(msg);
}

/**
 * @brief Set the auth chain
 * @param authChain
 */
void ngrt4n::setPassChain(char* authChain)
{
  std::ofstream ofpass;
  ofpass.open(ngrt4n::AUTH_FILE.c_str());
  if(!ofpass.good()) {
    std::clog << "Unable to set the authentication token." << "\n";
    exit(1);
  }
  ofpass << crypt(authChain, salt.c_str());
  ofpass.close();
}


/**
 * @brief Get the auth chain
 * @return
 */
std::string ngrt4n::getPassChain()
{
  std::string authChain;
  std::ifstream pfile;
  pfile.open (ngrt4n::AUTH_FILE.c_str());
  if(!pfile.good()) {
    std::clog << "Unable to load the application's settings" << "\n";
    exit(1);
  }

  pfile >> authChain;
  pfile.close();
  return authChain;
}


/**
 * @brief main
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char ** argv)
{
  progName = basename(argv[0]);
  int port = MonitorBroker::DefaultPort;
  bool foreground = false;
  bool useLivestatus = false;
  char opt;
  char* pass = NULL;
  static const char *shotOpt="DTPhvls:u:c:p:";
  while ((opt = getopt(argc, argv, shotOpt)) != -1) {
    switch (opt){
      case 'D':
        foreground = true;
        break;
      case 'l':
        useLivestatus = true;
        break;
      case 's':
        livestatusSocket = optarg;
        break;
      case 'u':
        unixcatPath = optarg;
        break;
      case 'c':
        statusFile = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        if(port <= 0 ) {
          std::cerr << "Bad port number\n";
          exit(1);
        }
        break;
      case 'P':
        ngrt4n::initApp();
        pass = getpass("Type a passphrase:");
        ngrt4n::setPassChain(pass);
        std::cout << ngrt4n::getPassChain()<<"\n";
        exit(0);
      case 'T':
        std::cout << ngrt4n::getPassChain()<<"\n";
        exit(0);
      case 'v':
        std::cout << getVersionMsg(progName)<<"\n";
        exit(0);
      case 'h':
        std::cout << help();
        exit(0);
      default:
        std::cout << help();
        exit(1);
    }
  }
  ngrt4n::initApp();
  authChain = ngrt4n::getPassChain();
  std::clog << getVersionMsg(progName)<<"\n";

  if(!foreground) {
    pid_t pid = fork();
    if(pid <= -1) {
      std::clog << "Failed while starting the daemon service\n";
      exit(1);
    } else if(pid > 0) {
      exit (0);
    }
    setsid();
  }

  std::ostringstream uri;
  uri << "tcp://0.0.0.0:" << port;
  ZmqSocket socket(ZMQ_REP);
  if(!socket.bind(uri.str())) {
    std::clog << "ERROR\n";exit(1);
  }

  std::clog << " == Binding address => "<<uri.str()<<"\n";
  if (useLivestatus) {
    std::clog << " == Using Livestatus socket => " << livestatusSocket <<"\n";
  } else {
    std::clog << " == Using Status dat file => " << statusFile <<"\n";
  }
  std::clog << " == Server started\n";

  MonitorBroker monitor(statusFile);
  while (true) {
    std::string recvMsg = socket.recv();
    std::string response;
    if(recvMsg == "PING") {
      response = "ALIVE:"+packageVersion;
    } else {
      size_t pos = recvMsg.find(":");
      std::string authToken = "";
      std::string data = "";
      if(pos != std::string::npos) {
        authToken = recvMsg.substr(0, pos);
        data = recvMsg.substr(pos+1, std::string::npos);
      }
      if(authToken == authChain) {
        if (! useLivestatus) {
          response = monitor.getInfOfService(data);
        } else {
          redirectRequestToLivestatus(data, response);
        }
      } else {
        response = "{\"return_code\" : \"-2\", \"message\" : \"Authentication failed\"}";
      }
    }
    socket.send(response);
  }
  return 0;
}
