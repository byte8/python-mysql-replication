# -*- coding: utf-8 -*-

import struct
import datetime
from collections import OrderedDict

from pymysql.util import byte2int, int2byte

def iter_bytes_to_string(hash):
    if issubclass(hash.__class__, {}.__class__):
        for key in hash.keys():
            if not issubclass(hash[key].__class__, {}.__class__):
                try:
                    hash[key] = bytes.decode(hash[key])
                except:
                    continue
            else:
                iter_bytes_to_string(hash[key])
    return hash


class BinLogEvent(object):
    def __init__(self, from_packet, event_size, table_map, ctl_connection,
                 only_tables = None,
                 only_schemas = None,
                 freeze_schema = False):
        self.packet = from_packet
        self.table_map = table_map
        self.event_type = self.packet.event_type
        self.timestamp = self.packet.timestamp
        self.event_size = event_size
        self.log_pos = self.packet.log_pos
        self._ctl_connection = ctl_connection
        # The event have been fully processed, if processed is false
        # the event will be skipped
        self._processed = True
        self.hashes = {}

    def _read_table_id(self):
        # Table ID is 6 byte
        # pad little-endian number
        table_id = self.packet.read(6) + int2byte(0) + int2byte(0)
        return struct.unpack('<Q', table_id)[0]

    def dump(self):
        self.hashes["class"] = self.__class__.__name__
        self.hashes["timestamp"] = self.timestamp
        self.hashes["log_pos"] = self.packet.log_pos
        self.hashes["event_size"] = self.event_size
        self.hashes["read_bytes"] = self.packet.read_bytes
        self.hashes["flags"] = self.packet.flags

        h = self._dump()
        if h:
            self.hashes.update(h)

        self.hashes = iter_bytes_to_string(self.hashes)
        # TODO
        # put_pos: last put pos of producer
        # get_pos: last get pos of consumer, get_pos = put_pos
        # exec_pos: last exec pos of consumer
        return self.hashes


    def _dump(self):
        """Core data dumped for the event"""
        pass

class GtidEvent(BinLogEvent):
    """GTID change in binlog event
    """
    def __init__(self, from_packet, event_size, table_map, ctl_connection, **kwargs):
        super(GtidEvent, self).__init__(from_packet, event_size, table_map,
                                          ctl_connection, **kwargs)

        self.commit_flag = byte2int(self.packet.read(1)) == 1
        self.sid = self.packet.read(16)
        self.gno = struct.unpack('<Q', self.packet.read(8))[0]
        self.__hashes = {}

    @property
    def gtid(self):
        """GTID = source_id:transaction_id
        Eg: 3E11FA47-71CA-11E1-9E33-C80AA9429562:23
        See: http://dev.mysql.com/doc/refman/5.6/en/replication-gtids-concepts.html"""
        gtid = "%s%s%s%s-%s%s-%s%s-%s%s-%s%s%s%s%s%s" %\
               tuple("{0:02x}".format(ord(c)) for c in self.sid)
        gtid += ":%d" % self.gno
        return gtid

    def _dump(self):
        self.__hashes["commit_flag"] = self.commit_flag
        self.__hashes["gtid"] = self.gtid
        return self.__hashes

    def __repr__(self):
        return '<GtidEvent "%s">' % self.gtid


class RotateEvent(BinLogEvent):
    """Change MySQL bin log file

    Attributes:
        position: Position inside next binlog
        next_binlog: Name of next binlog file
    """
    def __init__(self, from_packet, event_size, table_map, ctl_connection, **kwargs):
        super(RotateEvent, self).__init__(from_packet, event_size, table_map,
                                          ctl_connection, **kwargs)
        self.position = struct.unpack('<Q', self.packet.read(8))[0]
        self.next_binlog = self.packet.read(event_size - 8).decode()
        self.__hashes = {}

    def dump(self):
        self.__hashes["class"] = self.__class__.__name__
        self.__hashes["position"] = self.position
        self.__hashes["next_binlog"] = self.next_binlog
        self.__hashes["timestamp"] = self.timestamp
        return self.__hashes


class FormatDescriptionEvent(BinLogEvent):
    pass


class StopEvent(BinLogEvent):
    pass


class XidEvent(BinLogEvent):
    """A COMMIT event

    Attributes:
        xid: Transaction ID for 2PC
    """

    def __init__(self, from_packet, event_size, table_map, ctl_connection, **kwargs):
        super(XidEvent, self).__init__(from_packet, event_size, table_map,
                                       ctl_connection, **kwargs)
        # TODO
        self.__only_schemas = kwargs["only_schemas"]
        #self.schema = struct.unpack(, self.packet.read())
        self.xid = struct.unpack('<Q', self.packet.read(8))[0]
        self.__hashes = {}

    def _dump(self):
        super(XidEvent, self)._dump()
        self.__hashes["xid"] = self.xid
        return self.__hashes


class QueryEvent(BinLogEvent):
    '''This evenement is trigger when a query is run of the database.
    Only replicated queries are logged.'''
    def __init__(self, from_packet, event_size, table_map, ctl_connection, **kwargs):
        super(QueryEvent, self).__init__(from_packet, event_size, table_map,
                                         ctl_connection, **kwargs)

        self.__only_schemas = kwargs["only_schemas"]

        # Post-header
        self.slave_proxy_id = self.packet.read_uint32()
        self.execution_time = self.packet.read_uint32()
        self.schema_length = byte2int(self.packet.read(1))
        self.error_code = self.packet.read_uint16()
        self.status_vars_length = self.packet.read_uint16()

        # Payload
        self.status_vars = self.packet.read(self.status_vars_length)
        self.schema = self.packet.read(self.schema_length)
        self.packet.advance(1)

        self.query = self.packet.read(event_size - 13 - self.status_vars_length
                                      - self.schema_length - 1).decode("utf-8")
        #string[EOF]    query
        self.__hashes = {}

    def _dump(self):
        super(QueryEvent, self)._dump()
        self.__hashes["schema"] = bytes.decode(self.schema)
        self.__hashes["execution_time"] = self.execution_time
        self.__hashes["query"] = self.query
        return self.__hashes


class NotImplementedEvent(BinLogEvent):
    def __init__(self, from_packet, event_size, table_map, ctl_connection, **kwargs):
        super(NotImplementedEvent, self).__init__(
            from_packet, event_size, table_map, ctl_connection, **kwargs)
        self.packet.advance(event_size)
