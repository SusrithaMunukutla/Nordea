package com.nordeapsp.service.common.dao;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import com.nordeapsp.service.model.NPSPRisk;

public class RiskDAO {

	private DataSource dataSource;

	public void setDataSource(DataSource dataSource) {
		this.dataSource = dataSource;
	}

	public void create(NPSPRisk npspRisk) {
		String query = "insert into NORDEAPSP.npsprisk (" + "merchantid," + "card_ip_no,"
				+ "type," + "order_id," + "date_time" + ") values (?,?,?,?,?)";

		Connection con = null;
		PreparedStatement ps = null;
		try {

			con = dataSource.getConnection();
			ps = con.prepareStatement(query);
			ps.setString(1, npspRisk.getMerchantId());
			ps.setString(2, npspRisk.getCardipNo());
			ps.setString(3, npspRisk.getType());
			ps.setInt(4, npspRisk.getOrderid());
			Timestamp date = new java.sql.Timestamp(
					new java.util.Date().getTime());
			ps.setTimestamp(5, date);
			System.out.println("Order ID : " + npspRisk.getOrderid());
			int out = ps.executeUpdate();
			if (out != 0) {
				System.out
						.println("Risk Card/Ip Address saved for MErchant id="
								+ npspRisk.getMerchantId());
			} else
				System.out.println("Employee save failed with id="
						+ npspRisk.getMerchantId());
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				ps.close();
				con.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}

	public List<NPSPRisk> getRiskbyMerchant(String merchantid) {

		String query = "select merchantid,card_ip_no,type,date_time from  npsprisk where merchantid=?";
		List<NPSPRisk> npspRiskList = new ArrayList<NPSPRisk>();
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = dataSource.getConnection();
			ps = con.prepareStatement(query);
			ps.setString(1, merchantid);
			rs = ps.executeQuery();
			while (rs.next()) {
				NPSPRisk npspRisk = new NPSPRisk();
				npspRisk.setMerchantId(rs.getString("merchantid"));
				npspRisk.setCardipNo(rs.getString("card_ip_no"));
				npspRisk.setType(rs.getString("type"));

				DateFormat df = new SimpleDateFormat("YYYY-MM-dd:HH:mm:ss");
				String dateFormatted = df.format(rs.getTimestamp("date_time")
						.getTime());
				npspRisk.setDatetime(dateFormatted);
				npspRiskList.add(npspRisk);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				rs.close();
				ps.close();
				con.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		return npspRiskList;

	}

}
