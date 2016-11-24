package com.nordeapsp.service.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.nordeapsp.service.common.dao.RiskDAO;
import com.nordeapsp.service.dao.BlockedCardDAO;
import com.nordeapsp.service.dao.CustomerDAO;
import com.nordeapsp.service.dao.NegativeCheckDAO;
import com.nordeapsp.service.dao.OrderDAO;
import com.nordeapsp.service.dao.VelocityDAO;
import com.nordeapsp.service.model.Customer;
import com.nordeapsp.service.model.NPSPRisk;
import com.nordeapsp.service.model.NordeaPSPMessage;
import com.nordeapsp.service.model.Order;

@RestController
public class CardValidationController {

	@Autowired
	private VelocityDAO velocityDAO;

	@Autowired
	private OrderDAO orderDAO;

	@Autowired
	private BlockedCardDAO blockedCardDAO;

	@Autowired
	private NegativeCheckDAO negativeCheckDAO;

	@Autowired
	private RiskDAO riskDAO;
	
	@Autowired
	private CustomerDAO customerDAO;

	NordeaPSPMessage nordeaPSPMessage;

	Order order;

	boolean merchant_valocity;
	boolean negativeCheck;

	boolean blockedCard = false;

	int nordeaPSP_Code;
	int nordeaPSP_orderid = 0;
	String nordeaPSP_message;
	boolean nordeaPSP_Status;

	@GetMapping("/blockedCard/{merchantid}/{orderid}/{cardno}")
	public ResponseEntity getCardStatus(
			@PathVariable("merchantid") String merchantid,
			@PathVariable("orderid") int orderid,
			@PathVariable("cardno") Long cardno) {

		blockedCard = blockedCardDAO.get(cardno);
		if (blockedCard) {

			nordeaPSP_orderid = orderid;
			nordeaPSP_Code = 201;
			nordeaPSP_message = "Card no is blocked";
			nordeaPSP_Status = true;

			nordeaPSPMessage = setServiceMesasge(orderid, nordeaPSP_Code,
					nordeaPSP_message, nordeaPSP_Status);
			NPSPRisk npspRisk = new NPSPRisk();
			npspRisk.setOrderid(orderid);
			npspRisk.setCardipNo(String.valueOf(cardno));
			npspRisk.setMerchantId(merchantid);
			npspRisk.setType("BlockedCard");

			riskDAO.create(npspRisk);
			orderDAO.updateOrder(orderid, "Failed",0,"paytype");
			return new ResponseEntity(nordeaPSPMessage, HttpStatus.OK);
		}
		nordeaPSP_orderid = orderid;
		nordeaPSP_Code = 201;
		nordeaPSP_message = "Card no is valid";
		nordeaPSP_Status = false;

		nordeaPSPMessage = setServiceMesasge(orderid, nordeaPSP_Code,
				nordeaPSP_message, nordeaPSP_Status);

		return new ResponseEntity(nordeaPSPMessage, HttpStatus.OK);
	}

	@GetMapping("/velocity/{merchantid}/{orderid}")
	public ResponseEntity getMerchantVelocity(
			@PathVariable("merchantid") String merchantid,
			@PathVariable("orderid") int orderid) {

		merchant_valocity = velocityDAO.get(merchantid);

		if (merchant_valocity) {

			nordeaPSP_Code = 202;
			nordeaPSP_message = "Merchant Velocity is  with in approved Limit";
			nordeaPSP_Status = true;
			nordeaPSPMessage = setServiceMesasge(orderid, nordeaPSP_Code,
					nordeaPSP_message, nordeaPSP_Status);

			return new ResponseEntity(nordeaPSPMessage, HttpStatus.OK);
		}

		nordeaPSP_Code = 202;
		nordeaPSP_message = "Merchant Velocity is not with in approved Limit";
		nordeaPSP_Status = false;
		nordeaPSPMessage = setServiceMesasge(orderid, nordeaPSP_Code,
				nordeaPSP_message, nordeaPSP_Status);
		NPSPRisk npspRisk = new NPSPRisk();
		npspRisk.setCardipNo("Tx  Count or Amount Exceeds Limit");
		npspRisk.setMerchantId(merchantid);
		npspRisk.setType("Velocity");
		npspRisk.setOrderid(orderid);

		riskDAO.create(npspRisk);
		orderDAO.updateOrder(orderid, "Failed",0,"paytype");
		return new ResponseEntity(nordeaPSPMessage, HttpStatus.OK);
	}

	@GetMapping("/negativeCheck/{merchantid}/{orderid}/{ipaddress:.+}")
	public ResponseEntity getNegativeCheck(
			@PathVariable("merchantid") String merchantid,
			@PathVariable("orderid") int orderid,
			@PathVariable("ipaddress") String ipaddress) {

		System.out.println(" Negative check : " + ipaddress);

		negativeCheck = negativeCheckDAO.get(ipaddress);

		if (negativeCheck) {
			nordeaPSP_orderid = orderid;
			nordeaPSP_Code = 203;
			nordeaPSP_message = "Negative Check";
			nordeaPSP_Status = true;
			nordeaPSPMessage = setServiceMesasge(orderid, nordeaPSP_Code,
					nordeaPSP_message, nordeaPSP_Status);
			NPSPRisk npspRisk = new NPSPRisk();
			npspRisk.setOrderid(orderid);
			npspRisk.setCardipNo(ipaddress);
			npspRisk.setMerchantId(merchantid);
			npspRisk.setType("Invalid IP Address");

			riskDAO.create(npspRisk);
			orderDAO.updateOrder(orderid, "Failed",0,"paytype");
			return new ResponseEntity(nordeaPSPMessage, HttpStatus.OK);
		}
		nordeaPSP_orderid = orderid;
		nordeaPSP_Code = 203;
		nordeaPSP_message = "Valid IP Address";
		nordeaPSP_Status = false;
		nordeaPSPMessage = setServiceMesasge(orderid, nordeaPSP_Code,
				nordeaPSP_message, nordeaPSP_Status);

		return new ResponseEntity(nordeaPSPMessage, HttpStatus.OK);
	}

	@GetMapping("/users/{userid}/{password}")
	public ResponseEntity getUser(@PathVariable("userid") int userid,
			@PathVariable("password") String password) {

		Customer  customer = customerDAO.get(userid, password);

		if (customer != null) {
			
			nordeaPSP_orderid = userid;
			nordeaPSP_Code = 401;
			nordeaPSP_message = "Valid User";
			nordeaPSP_Status = true;
			nordeaPSPMessage = setServiceMesasge(nordeaPSP_orderid, nordeaPSP_Code,
					nordeaPSP_message, nordeaPSP_Status);

			return new ResponseEntity(customer, HttpStatus.OK);
		}
		nordeaPSP_orderid = userid;
		nordeaPSP_Code = 402;
		nordeaPSP_message = "Invalid User";
		nordeaPSP_Status = false;
		nordeaPSPMessage = setServiceMesasge(nordeaPSP_orderid, nordeaPSP_Code,
				nordeaPSP_message, nordeaPSP_Status);
		return new ResponseEntity(nordeaPSPMessage, HttpStatus.OK);
	}	
	
	public NordeaPSPMessage setServiceMesasge(int orderid, int messageid,
			String Message, boolean status) {
		nordeaPSPMessage = new NordeaPSPMessage();
		nordeaPSPMessage.setOrderid(orderid);
		nordeaPSPMessage.setMessageId(messageid);
		nordeaPSPMessage.setMessage(Message);
		nordeaPSPMessage.setStatus(status);
		return nordeaPSPMessage;
	}

}
