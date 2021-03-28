// App.java
package com.github.username;
//import com.github.username.TcpFlow;
import java.io.IOException;
import java.net.Inet4Address;
import java.util.*;
import com.sun.jna.Platform;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.TcpPort;


public class App {
static int count = 0;
static List<TcpFlow> flows = new ArrayList<>();
static List<TcpFlow> totalflows = new ArrayList<>();
static int check_number = 0;
static int UDP_number = 0;
static int TCP_number = 0;
static int ICMP_number = 0;
static float totalUDP = 0;
static float totalICMP = 0;
static float totalOther = 0;
static int other = 0;
static float total_byte = 0;
static boolean syn;
static double first_pack_time = 0;
static double last_pack_time = 0;
static boolean first_packet_time= false;
static boolean last_packet_time=false;

class TcpFlow{
	
String sip;
int srcPort;
String dip;
int dstPort;
boolean syn;
boolean fin;
int complete;
int incomplete;
int count;
float psize;
double start;
double end;
float total;


	public TcpFlow(String sip, int srcPort, String dip, int dstPort, boolean syn, boolean fin, int complete, int incomplete, int count, float psize, double start, double end, float total){
	this.sip = sip;
	this.dip = dip;
	
	this.srcPort = srcPort;	
	this.dstPort = dstPort;

	this.syn = syn;
	this.fin = fin;

	this.complete = complete;
	this.incomplete = incomplete;

	this.count = count;
	this.psize = psize;

	this.start = start;
	this.end = end;

	this.total = total;


	}
}

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        
        final PcapHandle handle;
        handle = Pcaps.openOffline(args[0]);
        PacketListener listener = new PacketListener() {
                public void gotPacket(Packet packet) {
			
                        
			if(first_packet_time==false)
			{
			first_pack_time = (double)handle.getTimestamp().getTime();
			first_packet_time=true;
			}
			last_pack_time = (double)handle.getTimestamp().getTime();
              					
			check_number = 1+ check_number;
		 	total_byte = total_byte + (float)packet.length();




			
			if(packet.get(TcpPacket.class)!=null){//TCP SUMMARY TABLE
			   TCP_number = TCP_number +1 ;

			IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
			TcpPacket tcpPacket = packet.get(TcpPacket.class);
                        Inet4Address srcAddr = ipV4Packet.getHeader().getSrcAddr();
			Inet4Address dstAddr = ipV4Packet.getHeader().getDstAddr();
			String sip = srcAddr.getHostAddress();
			String dip = dstAddr.getHostAddress();
			int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
			int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
			syn = tcpPacket.getHeader().getSyn();
			boolean fin = tcpPacket.getHeader().getFin();
			float psize = (float)packet.length();
			int complete = 0;
			int incomplete = 0;
			int count = 0;
			double start = 0;
			double end = 0;
			float total = psize;
			
			if(syn){
			start = (double)handle.getTimestamp().getTime()/1000000.0;
			}
			if(fin){
			end = (double)handle.getTimestamp().getTime()/1000000.0;
			}

			App a = new App();
		App.TcpFlow flow = a.new TcpFlow(sip,srcPort,dip,dstPort,syn,fin,complete,incomplete,count,psize,start,end,total);
			boolean exists = false;

			totalflows.add(flow);
			
			
			for(int j = 0; j < flows.size(); j++){

			if(Objects.equals(flows.get(j).sip, sip) && Objects.equals(flows.get(j).dip, dip) 				&& flows.get(j).srcPort == srcPort && flows.get(j).dstPort == dstPort){//If flows(j) equals flow
				exists = true;
			if(syn){
			flows.get(j).start = start;
			System.out.println("Working");
			}

			if(fin){
			flows.get(j).end = end;
			}
			
				//flows.get(j).count++;
				
				}//end of equals if
			}//end of for j loop
			
			if(!exists){
			flows.add(flow);
			totalflows.remove(totalflows.size()-1);
			}

			}//TCP SUMMARY TABLE END

			else if(packet.get(UdpPacket.class)!=null){
			   UDP_number = UDP_number + 1 ;
			   totalUDP = totalUDP + (float)packet.length();
			}
			else if(packet.get(IcmpV4CommonPacket.class)!=null){
			   ICMP_number = ICMP_number + 1 ;
			   totalICMP = totalICMP + (float)packet.length();
			}else{
			other = other + 1;
			totalOther = totalOther + (float)packet.length();
			}
		
                }
        };

        try {
                    int maxPackets = -1;
                        handle.loop(maxPackets, listener);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
            }
			
	double total_time = last_pack_time - first_pack_time;
	total_time = total_time/1000.0;

	for(int a = 0; a < flows.size(); a++){

	for(int b = 0; b < totalflows.size(); b++){
	if(Objects.equals(flows.get(a).sip, totalflows.get(b).sip) && Objects.equals(flows.get(a).dip, totalflows.get(b).dip) 				&& flows.get(a).srcPort == totalflows.get(b).srcPort && flows.get(a).dstPort == totalflows.get(b).dstPort){
	
	

	//flows.get(a).psize += totalflows.get(b).psize;
	if(!totalflows.get(b).syn && !flows.get(a).syn){
	flows.get(a).incomplete++;
	flows.get(a).total+=totalflows.get(b).psize;
	}
	if(flows.get(a).syn && !totalflows.get(b).fin){
	flows.get(a).count++;
	flows.get(a).psize+=totalflows.get(b).psize;
	flows.get(a).total+=totalflows.get(b).psize;
	}
	
	if(totalflows.get(a).syn){
	//System.out.println("1");
	flows.get(a).psize += totalflows.get(b).psize;
	flows.get(a).syn = true;
	flows.get(a).fin = false;
	}
	

	if(totalflows.get(b).fin && flows.get(a).syn){
	//flows.get(a).total+=totalflows.get(b).total;
	flows.get(a).fin = true;
	flows.get(a).syn = false;
	flows.get(a).complete += flows.get(a).count+1;
	flows.get(a).psize += totalflows.get(b).psize;
	flows.get(a).total+=totalflows.get(b).psize;
	flows.get(a).count = 0;
	}
	

	}//end equals loop
	}//end b loop
	flows.get(a).incomplete += flows.get(a).count;

	
	}//end a loop
	
	System.out.println("TCP Summary Table");
	for(int i = 0; i < flows.size(); i++){

		if(flows.get(i).complete > 1){
		System.out.println(flows.get(i).sip + ", " + flows.get(i).srcPort + ", " + flows.get(i).dip + ", " + 			flows.get(i).dstPort + ", " + flows.get(i).complete + ", " + flows.get(i).incomplete + ", " + (flows.get(i).total) + ", " + (((flows.get(i).psize)*8.0)/1000000)/(flows.get(i).end - flows.get(i).start));
		}else
		System.out.println(flows.get(i).sip + ", " + flows.get(i).srcPort + ", " + flows.get(i).dip + ", " + 			flows.get(i).dstPort + ", " + flows.get(i).complete + ", " + flows.get(i).incomplete);

		
	}
	System.out.println("Additional Protocols Summary Table");
	System.out.println( "UDP, " + UDP_number + ", " + totalUDP);
	System.out.println( "ICMP, " + ICMP_number + ", " + totalICMP);
	System.out.println( "Other, " + other + ", " + totalOther);

        // Cleanup when complete
        handle.close();
    }
}

