package packetsNetFilterDB;
import java.sql.*;
public class SqliteDB {

	// TODO: USING class.classToLongBits 
	private Connection con;
	
	
	public SqliteDB(String url) throws SQLException
	{
		con=DriverManager.getConnection(url);
	}
	
	public boolean createTable(String tableName,String fields)throws SQLException
	{
		boolean res=false;
		try {
		Statement stmt=con.createStatement();
		stmt.executeUpdate("CREATE TABLE IF NOT EXISTS "+tableName+" ("+fields+")");
		res= true;
		}
		catch(SQLException e)
		{
			System.out.println(e.getMessage());
		}
		return res;
	}
	public boolean InsertInto(String tableName,ProtocolItem item,int serialNumber) throws SQLException
	{
		boolean res=false;
		PreparedStatement prpStmt = con.prepareStatement("INSERT INTO "+tableName+" VALUES (?,?,?,?,?,?)");
		prpStmt.setString(1, item.getIp());
		prpStmt.setInt(2, item.getPort());
		prpStmt.setString(3,item.getTypeOfProperty());
		prpStmt.setString(4, item.getMaxRange()/*turnIntoDoubleBits(item.getTypeOfProperty(),item.getMaxRange())*/);
		prpStmt.setString(5, item.getMinRange()/*turnIntoDoubleBits(item.getTypeOfProperty(),item.getMinRange())*/);
		prpStmt.setInt(6, serialNumber);
		
		prpStmt.executeUpdate();
		return res;
	}
	/*
	public double turnIntoDoubleBits(String typeOfProperty,Object range)
	{
		switch(typeOfProperty)
		{
		 case "INT":return Double.valueOf(range.toString());
		 case "FLOAT":return Double.valueOf(range.toString());
		 case "CHAR":return Double.valueOf(range.toString().charAt(0));
		 default: return 0;
		}
	}*/
}
