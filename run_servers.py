import sys
from utils.ftp_server import server
from utils.web_server import web_server_thread

if __name__ == "__main__":
    print("\n" + "="*70)
    print(" CYBER SECURITY LLM AGENTS - Server Module")
    print("="*70)
    print("\nStarting servers...")
    print("  - Web Server (HTTP)")
    print("  - FTP Server")
    print("\n[INFO] Press Ctrl+C to stop all servers")
    print("="*70 + "\n")
    
    try:
        # Start WEB server
        web_server_thread.start()
        print("[OK] Web server started successfully")
        
        # Start FTP server (blocking call)
        print("[OK] FTP server started successfully")
        print("\n[INFO] Servers are running. Waiting for connections...\n")
        server.serve_forever()
        
    except KeyboardInterrupt:
        print("\n\n[INFO] Shutting down servers...")
        print("[OK] Servers stopped successfully. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Failed to start servers: {e}")
        sys.exit(1)
