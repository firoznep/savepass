import net from "node:net";
import tls from "node:tls";

const CRLF = "\r\n";
const DEFAULT_TIMEOUT = 20000;

function parseResponse(buffer: string): string {
  const lines = buffer.trim().split(/\r?\n/);
  return lines[lines.length - 1];
}

function readResponse(socket: net.Socket): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error("SMTP response timeout"));
    }, DEFAULT_TIMEOUT);

    function onData(chunk: Buffer) {
      data += chunk.toString("utf8");
      const lines = data.split(/\r?\n/);
      const lastLine = lines[lines.length - 2];
      if (!lastLine) {
        return;
      }
      if (/^[0-9]{3} /.test(lastLine)) {
        cleanup();
        resolve(data);
      }
    }

    function onError(err: Error) {
      cleanup();
      reject(err);
    }

    function cleanup() {
      clearTimeout(timeout);
      socket.off("data", onData);
      socket.off("error", onError);
    }

    socket.on("data", onData);
    socket.on("error", onError);
  });
}

async function sendCommand(
  socket: net.Socket,
  command: string,
): Promise<string> {
  socket.write(`${command}${CRLF}`);
  return readResponse(socket);
}

async function createConnection(
  host: string,
  port: number,
  secure: boolean,
): Promise<net.Socket> {
  if (secure) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect(
        { host, port, servername: host, rejectUnauthorized: false },
        () => {
          resolve(socket);
        },
      );
      socket.on("error", reject);
    });
  }

  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port }, () => {
      resolve(socket);
    });
    socket.on("error", reject);
  });
}

async function upgradeToTls(
  socket: net.Socket,
  host: string,
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const tlsSocket = tls.connect(
      { socket, host, servername: host, rejectUnauthorized: false },
      () => {
        resolve(tlsSocket);
      },
    );
    tlsSocket.on("error", reject);
  });
}

function dotEscape(message: string): string {
  return message.replace(/^(\.|\r?\n\.)/gm, "..$1");
}

export interface SendMailOptions {
  to: string;
  subject: string;
  text: string;
  from?: string;
}

export async function sendMail({ to, subject, text, from }: SendMailOptions) {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || "465");
  const username = process.env.SMTP_USER;
  const password = process.env.SMTP_PASS;
  const secure =
    (process.env.SMTP_SECURE || "true").toLowerCase() === "true" ||
    port === 465;
  const sender = from || process.env.SMTP_FROM || `no-reply@${host}`;

  if (!host) {
    throw new Error("SMTP_HOST is not configured.");
  }

  let socket = await createConnection(host, port, secure);
  try {
    let response = await readResponse(socket);
    if (!response.startsWith("220")) {
      throw new Error(`SMTP server not ready: ${response}`);
    }

    response = await sendCommand(socket, `EHLO ${host}`);
    if (!response.startsWith("250")) {
      throw new Error(`EHLO failed: ${response}`);
    }

    if (!secure && /STARTTLS/m.test(response)) {
      response = await sendCommand(socket, "STARTTLS");
      if (!response.startsWith("220")) {
        throw new Error(`STARTTLS failed: ${response}`);
      }
      socket = await upgradeToTls(socket, host);
      response = await sendCommand(socket, `EHLO ${host}`);
      if (!response.startsWith("250")) {
        throw new Error(`EHLO after STARTTLS failed: ${response}`);
      }
    }

    if (username && password) {
      response = await sendCommand(socket, "AUTH LOGIN");
      if (!response.startsWith("334")) {
        throw new Error(`SMTP auth failed: ${response}`);
      }
      response = await sendCommand(
        socket,
        Buffer.from(username).toString("base64"),
      );
      if (!response.startsWith("334")) {
        throw new Error(`SMTP auth username rejected: ${response}`);
      }
      response = await sendCommand(
        socket,
        Buffer.from(password).toString("base64"),
      );
      if (!response.startsWith("235")) {
        throw new Error(`SMTP auth password rejected: ${response}`);
      }
    }

    response = await sendCommand(socket, `MAIL FROM:<${sender}>`);
    if (!response.startsWith("250")) {
      throw new Error(`MAIL FROM rejected: ${response}`);
    }

    response = await sendCommand(socket, `RCPT TO:<${to}>`);
    if (!response.startsWith("250") && !response.startsWith("251")) {
      throw new Error(`RCPT TO rejected: ${response}`);
    }

    response = await sendCommand(socket, "DATA");
    if (!response.startsWith("354")) {
      throw new Error(`DATA command rejected: ${response}`);
    }

    const message = [
      `From: ${sender}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: 7bit",
      "",
      dotEscape(text),
      ".",
    ].join(CRLF);

    response = await sendCommand(socket, message);
    if (!response.startsWith("250")) {
      throw new Error(`Message not accepted: ${response}`);
    }

    await sendCommand(socket, "QUIT");
  } finally {
    socket.end();
  }
}
