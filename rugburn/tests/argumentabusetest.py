###
### Copyright 2002 Ximian, Inc.
###
### This program is free software; you can redistribute it and/or modify
### it under the terms of the GNU General Public License as published by
### the Free Software Foundation, version 2 of the License.
###
### This program is distributed in the hope that it will be useful,
### but WITHOUT ANY WARRANTY; without even the implied warranty of
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
### GNU General Public License for more details.
###
### You should have received a copy of the GNU General Public License
### along with this program; if not, write to the Free Software
### Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
###

###
### This test calls our xml-rpc methods with all sorts of broken
### arguments.
###

class ArgumentAbuseTest(burntest.BurnTest):

    def name(self):
        return "argument-abuse"

    def priority(self):
        return 1000

    def call_method(self, server, method_str, args):

        if self.short_circuit:
            return

        call = "server.%s%s" % (method_str, str(args))
        self.message("Calling %s%s" % (method_str, str(args)))

        try:
            eval(method_str + str(args))
        except ximian_xmlrpclib.Fault, f:
            if not f.faultCode in (-501,  # type error
                                   -502,  # wrong number of args
                                   -503,  # invalid pkg stream type
                                   -600,  # permission denied
                                   -601,  # unable to find package
                                   -606,  # bad channel
                                   -607,  # no transaction w/ that id
                                   -608): # no pref found
                raise

        try:
            ping = server.rcd.system.ping()
        except:
            self.error("Can't ping server -- it probably crashed")
            self.short_circuit = 1
        

    def abuse(self, server, method):

        # no arguments
        self.call_method(server, method, ())

        args = ()
        for x in range(1,5):
            args = args + (x,)
            self.call_method(server, method, args)

        args = ()
        for x in range(1,5):
            args = args + (str(x),)
            self.call_method(server, method, args)

        args = ()
        for x in range(1,5):
            args = args + (x * 3.14159,)
            self.call_method(server, method, args)

    def test(self, server):

        # System methods
        for x in ("ping",
                  "query_module",
                  "poll_pending",
                  "get_all_pending"):
            self.abuse(server, "server.rcd.system." + x)

        # News methods
        self.abuse(server, "server.rcd.news.get_all")

        # Log methods
        self.abuse(server, "server.rcd.log.query_log")

        # Prefs methods
        for x in ("get_pref",
                  "set_pref",
                  "list_prefs"):
            self.abuse(server, "server.rcd.prefs." + x)

        # Packsys methods
        for x in ("search",
                  "query_file",
                  "find_latest_version",
                  "package_info",
                  "package_dependency_info",
                  #"get_updates",
                  "update_summary",
                  "resolve_dependencies",
                  #"verify_dependencies",
                  "transact",
                  "abort_download",
                  "what_provides",
                  "what_requires",
                  "what_conflicts",
                  #"dump",
                  "get_channels",
                  "refresh_channel",
                  #"refresh_all_channels",
                  "get_channel_icon",
                  "subscribe",
                  "unsubscribe",
                  "world_sequence_number"):
            self.abuse(server, "server.rcd.packsys." + x)


        
burntest.register(ArgumentAbuseTest)
