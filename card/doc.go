// Package card provides owned OpenPGP Card sessions over selected transports.
// Device serializes complete workflows; separate method calls are not atomic.
// Protected operations accept an AuthenticationSource and keep VERIFY and the
// operation under one gate. Nil uses the current verification state. Sources
// run before the gate and transfer ownership of their returned password buffer.
//
// DeviceInvalidatedError closes the session; later calls return io.ErrClosedPipe.
// Waiting for an operation respects its context. Close interrupts I/O according
// to the transport's contract without waiting for the operation gate.
//
// Passwords must already use the card's encoding, including any KDF. Device
// neither caches authentication state, passwords, metadata or keys nor retries
// commands.
//
// Source organization follows OpenPGP Card 3.4.1: metadata.go covers Sec. 4.1;
// application.go and the named data-object files cover Secs. 4.2-4.4. Commands
// and their variants appear in specification order in commands.go (Sec. 7.2).
// SELECT DATA is part of the atomic certificate workflows in certificate.go;
// GET RESPONSE is handled by the transport. Temporary MSE bindings are managed
// in mse.go (Sec. 7.2.18), and secure_messaging.go opens sessions for Sec. 7.5.
// card.go owns the session; authentication.go and the signing files implement
// the operation gate and Go crypto.Signer workflows.
package card
