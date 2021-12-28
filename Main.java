package packetsNetFilterDB;
import java.util.*;
import java.util.List;
import java.sql.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
public class Main {

	public static void main(String[] args) throws SQLException {
		// TODO Auto-generated method stub
		SqliteDB sqlitedb=new SqliteDB("jdbc:sqlite:"+System.getProperty("user.home")+"/Desktop/EyalJavaProgram/packetsNetFilterDB/netFilterDB.sqlite");
		   ArrayList<ProtocolItem> properties=new ArrayList<ProtocolItem>(); 
		   String types[]= {"INT","CHAR","FLOAT","STRING","BOOLEAN","DOUBLE"};
	       JFrame frm=new JFrame("netFilterDBApplication");
	       JButton finished_button=new JButton("Click me if you have finished creating the structure"); 
	       finished_button.setBounds(200,700,400,50);
	       JButton addProperty_button=new JButton("Click me to add a property to the structure");
	       addProperty_button.setBounds(200, 630, 400, 50);
	       frm.add(finished_button); 
	       frm.add(addProperty_button);
	       
	       JLabel ipLabel=new JLabel("Enter ip for the netfilter protocol:"); 
	       ipLabel.setBounds(40,40,250,100);
	       frm.add(ipLabel);
	       JTextField ipTextField=new JTextField();
	       ipTextField.setBounds(300,70,200,50);
	       frm.add(ipTextField);
	       
	       JLabel portLabel=new JLabel("Enter port for the netfilter protocol:");
	       portLabel.setBounds(40,150,270,100);
	       frm.add(portLabel);
	       JTextField portTextField=new JTextField();
	       portTextField.setBounds(320,180,200,50);
	       frm.add(portTextField);
	       
	       JLabel typeLabel=new JLabel("Choose type:");
	       typeLabel.setBounds(40,260, 150, 100);
	       frm.add(typeLabel);
	       JComboBox cbTypes=new JComboBox(types);
	       cbTypes.setBounds(200, 290, 200, 50);
	       frm.add(cbTypes);
	       
	       JLabel minRangeLabel=new JLabel("Enter minimum range of value:");
	       minRangeLabel.setBounds(40,400,250,50);
	       frm.add(minRangeLabel);
	       JTextField minRangeTextField=new JTextField();
	       minRangeTextField.setBounds(300, 400, 200, 50);
	       frm.add(minRangeTextField);
	       
	       JLabel maxRangeLabel=new JLabel("Enter maximum range of value:");
	       maxRangeLabel.setBounds(40, 500, 250, 50);
	       frm.add(maxRangeLabel);
	       JTextField maxRangeTextField=new JTextField();
	       maxRangeTextField.setBounds(300, 500, 200, 50);
	       frm.add(maxRangeTextField);
	       
	       addProperty_button.addActionListener(new ActionListener()
	    		   {
	    	          @Override
	    	          public void actionPerformed(ActionEvent e)
	    	          {
	    	        	String ip=ipTextField.getText();
	    	        	int port=Integer.parseInt(portTextField.getText());
	    	        	String type=cbTypes.getSelectedItem().toString();
	    	        	String minRange=minRangeTextField.getText();
	    	        	String maxRange=maxRangeTextField.getText();
	    	        	properties.add(new ProtocolItem(ip,port,type,minRange,maxRange));
	    	        	JOptionPane.showMessageDialog(null, "succsessfuly added");
	    	          }
	    		   });
	       
	       finished_button.addActionListener(new ActionListener()
	    		   {
	    	          @Override
	    	          public void actionPerformed(ActionEvent e)
	    	          {
	    	        	  int i=0;
	    	        	  try 
	    	        	  {
							sqlitedb.createTable("Protocols", "ip TEXT NOT NULL,port INTEGER NOT NULL,type TEXT NOT NULL,minRange TEXT,maxRange TEXT,serialNUmber INTEGER");
						  } 
	    	        	  catch (SQLException e1)
	    	        	  {
							JOptionPane.showMessageDialog(null, e1.toString());
						  }
	    	        	  for(ProtocolItem item:properties)
	    	        	  {
	    	        		  try 
	    	        		  {
								sqlitedb.InsertInto("Protocols", item,i);
							  } 
	    	        		  catch (SQLException e1) 
	    	        		  {
	    	        			  JOptionPane.showMessageDialog(null, e1.toString());
							  }
	    	        		  i++;
	    	        	  }
	    	        	  JOptionPane.showMessageDialog(null, "succsessfuly structure added");
	    	        	  i=0;
	    	          }
	    		   }
	    		   );
	       
	       
	       frm.setLayout(null); 
	       frm.setSize(800,800);   
	       frm.setVisible(true);
	       frm.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	       
	    
	}
}
