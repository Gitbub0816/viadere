import ViadereCore
import enum ViadereCore.Channel

/// `Channel` collides with NIO's `Channel` in files that import Vapor/NIO; this alias gives tests and
/// other modules an unambiguous name for the Viadere delivery channel.
public typealias DeliveryChannel = Channel
