package de.hpi.ddm.actors;

import akka.actor.AbstractLoggingActor;
import akka.actor.ActorRef;
import akka.actor.PoisonPill;
import akka.actor.Props;
import akka.cluster.Cluster;
import akka.cluster.ClusterEvent.CurrentClusterState;
import akka.cluster.ClusterEvent.MemberRemoved;
import akka.cluster.ClusterEvent.MemberUp;
import akka.cluster.Member;
import akka.cluster.MemberStatus;
import de.hpi.ddm.structures.BloomFilter;
import de.hpi.ddm.systems.MasterSystem;
import de.hpi.ddm.utils.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class Worker extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "worker";

	public static Props props() {
		return Props.create(Worker.class);
	}

	public Worker() {
		this.cluster = Cluster.get(this.context().system());
		this.largeMessageProxy = this.context().actorOf(LargeMessageProxy.props(), LargeMessageProxy.DEFAULT_NAME);
	}

	////////////////////
	// Actor Messages //
	////////////////////

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class WelcomeMessage implements Serializable {
		private static final long serialVersionUID = 8343040942748609598L;
		private BloomFilter welcomeData;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class ComputingMessage implements Serializable {
		private User user;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class ComputePasswordMessage implements Serializable {
		private User user;
		private List<String> hints;
	}

	/////////////////
	// Actor State //
	/////////////////

	private Member masterSystem;
	private final Cluster cluster;
	private final ActorRef largeMessageProxy;
	private long registrationTime;

	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	@Override
	public void preStart() {
		Reaper.watchWithDefaultReaper(this);

		this.cluster.subscribe(this.self(), MemberUp.class, MemberRemoved.class);
	}

	@Override
	public void postStop() {
		this.cluster.unsubscribe(this.self());
	}

	////////////////////
	// Actor Behavior //
	////////////////////

	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(CurrentClusterState.class, this::handle)
				.match(MemberUp.class, this::handle)
				.match(MemberRemoved.class, this::handle)
				.match(WelcomeMessage.class, this::handle)
				.match(ComputingMessage.class, this::handle)
				.match(ComputePasswordMessage.class, this::handle)
				// TODO: Add further messages here to share work between Master and Worker actors
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(CurrentClusterState message) {
		message.getMembers().forEach(member -> {
			if (member.status().equals(MemberStatus.up()))
				this.register(member);
		});
	}

	private void handle(MemberUp message) {
		this.register(message.member());
	}

	private void register(Member member) {
		if ((this.masterSystem == null) && member.hasRole(MasterSystem.MASTER_ROLE)) {
			this.masterSystem = member;

			this.getContext()
					.actorSelection(member.address() + "/user/" + Master.DEFAULT_NAME)
					.tell(new Master.RegistrationMessage(), this.self());

			this.registrationTime = System.currentTimeMillis();
		}
	}

	private void handle(MemberRemoved message) {
		if (this.masterSystem.equals(message.member()))
			this.self().tell(PoisonPill.getInstance(), ActorRef.noSender());
	}

	private void handle(WelcomeMessage message) {
		final long transmissionTime = System.currentTimeMillis() - this.registrationTime;
		this.log().info("WelcomeMessage with " + message.getWelcomeData().getSizeInMB() + " MB data received in " + transmissionTime + " ms.");
	}

	private void handle(ComputingMessage message) {
		User u = message.getUser();
		this.log().info("ComputingMessage received");
		char[] a = u.getPasswordChars().toCharArray();
		// test all permutation of password and compare them to hash
		List<String> crackedHints = new ArrayList<>();
		heapPermutation(a, a.length, u.getPasswordLength(), crackedHints, u.getHashedHints());

		// send crackedHints to Master
		Master.ResultHashHintsMessage message1 = new Master.ResultHashHintsMessage(u, crackedHints);
		this.getContext()
				.actorSelection(masterSystem.address() + "/user/" + Master.DEFAULT_NAME)
				.tell(message1, this.self());
		ComputePasswordMessage computeMsg = new ComputePasswordMessage(
				u,
				crackedHints
		);
		this.handle(computeMsg);

	}

	private void handle(ComputePasswordMessage message) {
		User u = message.getUser();
		// search for char not used in hints
		String characters = new String(Worker.charNotUsed(message.getHints(), u.getPasswordChars()));

		Optional<String> password = crackedPassword(characters, u.getPasswordLength(), u.getHashedPassword());
		// if password's hash match with the hash given we found the password
		password.ifPresent(p -> {
			// send password to Master
			Master.ResultPasswordMessage message1 = new Master.ResultPasswordMessage(u, p);
			this.getContext()
					.actorSelection(masterSystem.address() + "/user/" + Master.DEFAULT_NAME)
					.tell(message1, this.self());
		});
	}

	public static char[] charNotUsed(List<String> hints, String passwordChars) {
		StringBuilder charArray = new StringBuilder();
		int i =0;
		for (int j = 0; j < passwordChars.length(); j++) {
			while(i < hints.size() && hints.get(i).indexOf(passwordChars.charAt(j)) >= 0) {
				// true : i < hints length and the letter is in the hint
				i++;
			}
			// exit : i >= hints length OR letter not in hint
			if(i >= hints.size()) {
				charArray.append(passwordChars.charAt(j));
			}
			i = 0;
		}
		char[] c =  charArray.toString().toCharArray();
		Arrays.sort(c);
		return c;
	}

	private String hash(String characters) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashedBytes = digest.digest(String.valueOf(characters).getBytes(StandardCharsets.UTF_8));

			StringBuilder stringBuffer = new StringBuilder();
			for (byte hashedByte : hashedBytes) {
				stringBuffer.append(Integer.toString((hashedByte & 0xff) + 0x100, 16).substring(1));
			}
			return stringBuffer.toString();
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	// Generating all permutations of an array using Heap's Algorithm
	// https://en.wikipedia.org/wiki/Heap's_algorithm
	// https://www.geeksforgeeks.org/heaps-algorithm-for-generating-permutations/
	private void heapPermutation(char[] a, int size, int n, List<String> l, List<String> hashedHints) {
		// If size is 1, store the obtained permutation
		if(hashedHints.size() == l.size()) return;
		if (size == 1) {
			String s = new String(a);
			if(n <= s.length()) s = s.substring(0, n);
			if(hashedHints.contains(hash(s))) l.add(s);
		}
		for (int i = 0; i < size; i++) {
			heapPermutation(a, size - 1, n, l, hashedHints);

			// If size is odd, swap first and last element
			char temp;
			if (size % 2 == 1) {
				temp = a[0];
				a[0] = a[size - 1];
			}

			// If size is even, swap i-th and last element
			else {
				temp = a[i];
				a[i] = a[size - 1];
			}
			a[size - 1] = temp;
		}
	}

	private Optional<String> crackedPassword(String characters, int size, String passwordHash) {
		return crackedPasswordHelper(characters, size, "", passwordHash);
	}

	private Optional<String> crackedPasswordHelper(String characters, int size, String currentCombination, String passwordHash) {
		if (currentCombination.length() == size) {
			if (hash(currentCombination).equals(passwordHash)) {
				return Optional.of(currentCombination);
			}
			return Optional.empty();
		}

		for (int i = 0; i < characters.length(); i++) {
			char c = characters.charAt(i);
			Optional<String> result = crackedPasswordHelper(characters, size, currentCombination + c, passwordHash);
			if (result.isPresent()) {
				return result;
			}
		}
		return Optional.empty();
	}
}