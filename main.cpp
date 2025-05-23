#include <cstdint> // For uint8_t, uint16_t
#include <cstring> // For memcpy
#include <iostream>
#include <map>
#include <vector>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>

#include "CustomPacket.h"
#include "MissingPacketsException.h"
#include "Peer.h"
#include "imgui/imgui.h"
#include "imgui/backends/imgui_impl_glfw.h"
#include "imgui/backends/imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <thread>
#include <vector>
#include <string>

std::mutex cout_mutex;

// flags:
// bit7  bit6    bit5      bit4       bit3       bit2        bit1   bit0 
// enc ---  msg_type  start_trans  end_trans   series     ACK       URGENT
//
//
// msg_type: 0 text, 1 file
//  Define Packet Structure

void print_and_verify_bits0_5(CustomPacket packet) {
  std::cout << "Initial MsgType: " << packet.getMsgType() << std::endl;
  packet.setMsgType(1); // File
  std::cout << "Updated MsgType: " << packet.getMsgType() << std::endl;

  std::cout << "Initial ACK flag: " << packet.get_ack_flag() << std::endl;
  packet.set_ack_flag();
  std::cout << "Updated ACK flag: " << packet.get_ack_flag() << std::endl;

  std::cout << "Initial End Transmission flag: " << packet.get_end_transmition_flag() << std::endl;
  packet.set_end_transmition_flag();
  std::cout << "Updated End Transmission flag: " << packet.get_end_transmition_flag() << std::endl;

  std::cout << "Initial Start Transmission flag: " << packet.get_start_transmition_flag() << std::endl;
  packet.set_start_transmition_flag();
  std::cout << "Updated Start Transmission flag: " << packet.get_start_transmition_flag() << std::endl;

  std::cout << "Initial Urgent flag: " << packet.get_urgent_flag() << std::endl;
  packet.set_urgent_flag();
  std::cout << "Updated Urgent flag: " << packet.get_urgent_flag() << std::endl;
}

void test_packet_serialization() {
  // Create a test packet
  CustomPacket packet;
  packet.packet_id = 1;
  packet.setMsgType(0); // Text message
  packet.set_ack_flag();
  packet.set_start_transmition_flag();
  strcpy(packet.payload, "Hello, custom protocol!"); // Set payload
  packet.length = strlen(packet.payload);           // Set length
  packet.checksum = packet.calculateChecksum();     // Calculate checksum

  // Print the original packet details
  std::cout << "Original Packet Details:\n";
  std::cout << "Packet ID: " << packet.packet_id << "\n";
  std::cout << "Message Type: " << (int)packet.getMsgType() << "\n";
  std::cout << "Payload: " << packet.payload << "\n";
  std::cout << "Length: " << packet.length << "\n";
  std::cout << "Checksum: " << packet.checksum << "\n";
  packet.printFlags();

  // Serialize the packet
  uint8_t buffer[sizeof(CustomPacket)];
  packet.serialize(buffer);

  // Deserialize the packet
  CustomPacket received = CustomPacket::deserialize(buffer);

  // Print the deserialized packet details
  std::cout << "\nDeserialized Packet Details:\n";
  std::cout << "Packet ID: " << received.packet_id << "\n";
  std::cout << "Message Type: " << (int)received.getMsgType() << "\n";
  std::cout << "Payload: " << received.payload << "\n";
  std::cout << "Length: " << received.length << "\n";
  std::cout << "Checksum: " << received.checksum << "\n";
  received.printFlags();

  // Verify the deserialized packet
  if (received.packet_id == packet.packet_id &&
      received.getMsgType() == packet.getMsgType() &&
      strcmp(received.payload, packet.payload) == 0 &&
      received.length == packet.length &&
      received.checksum == packet.checksum) {
    std::cout << "\nTest passed: Packet serialization and deserialization are correct.\n";
  } else {
    std::cout << "\nTest failed: Packet serialization and deserialization are incorrect.\n";
  }
}

void test_fragment_and_compose_message() {
  // Create a long message to be fragmented
  std::string long_message = "Site-ul are în pagina (pagina textit) două butoare disponibile extit șiextit, al doilea "
                             "fiind pentru crearea de utilizator nou al aplicației (orice utilizator va trebui să-și facă cont pentru a putea cumpăra bilete), "
                             "iar primul pentru a te conecta la un cont deja existent. "
                             "Pentru conectarea la un cont este nevoie doar de textitși de textit{parola} contului. Conectarea la un cont ne va oferi "
                             "posibilitatea de a vizualiza istoricul biletelor cumpărate (dacă există), cursele ce vor avea loc și lista locurilor libere din avion. "
                             "Prin apăsarea pe un loc liber, acel bilet va fi adaugat în coșul utilizatorului. Această acțiune poate fi repetată pentru posibilitatea "
                             "cumpărării a multiple bilete simultan. "
                             "Dacă în coș se află cel puțin un bilet, vor apărea două butoane: textit{} și textit{}, ce vor oferi posibilitatea de a șterge din coșul "
                             "curent biletul selectat, dar și de a finaliza cumpărarea, adăugând biletele în istoric și golind coșul.";
  uint16_t packet_id = 0;

  // Fragment the message
  std::map<uint16_t, CustomPacket> fragmented_packets = CustomPacket::fragmentMessage(long_message, packet_id);

  // Print fragmented packets
  std::cout << "Fragmented Packets:\n";
  for (const auto &pair : fragmented_packets) {
    const CustomPacket &packet = pair.second;
    std::cout << "Packet ID: " << packet.packet_id << ", Payload: " << packet.payload << ", Checksum: " << packet.checksum << ", length: "<< packet.length<<"\n\n";
  }

  // fragmented_packets.erase(2);
  if (fragmented_packets.find(2) != fragmented_packets.end()){
    fragmented_packets[2].checksum = 1243;
  }
  std::cout << "Fragmented Packets:\n";
  for (const auto &pair : fragmented_packets) {
    const CustomPacket &packet = pair.second;
    std::cout << "Packet ID: " << packet.packet_id << ", Payload: " << packet.payload << ", Checksum: " << packet.checksum << ", length: "<< packet.length<<"\n\n";
  }


  try {
  // Compose the message from fragmented packets
  std::string composed_message = CustomPacket::composedMessage(fragmented_packets);

  // Print the composed message
  std::cout << "\n\nComposed Message: " << composed_message << "\n";
  std::cout << "Composed Message size: " << composed_message.length() << "\n";


  } catch (const MissingPacketsException& e) {
    std::cerr <<"Error: " << e.what() <<std::endl;
    const std::vector<uint16_t>& missing_packets = e.getMissingPackets();

    for (const uint16_t missing_packet_id : missing_packets) {
      std::cout<<missing_packet_id << std::endl;
    }

  }catch (const std::exception& e) {
    std::cerr<<"Error: " << e.what()<<std::endl;
  }

}

void test_peer_class() {
  // Mutex and condition variable for thread synchronization
  std::mutex sync_mutex;
  std::condition_variable server_ready_cv;
  bool server_ready = false;

  // Mutex for thread-safe output
  std::mutex cout_mutex;

  // Peer 1: Server
  std::thread server_thread([&]() {
    Peer server_peer;
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Starting server peer on port 8080...\n";
    }

    // Start the server
    server_peer.startPeer();

    // Notify the client that the server is ready
    {
      std::lock_guard<std::mutex> lock(sync_mutex);
      server_ready = true;
    }
    server_ready_cv.notify_one();

    // Keep the server running
    std::this_thread::sleep_for(std::chrono::seconds(10)); // Simulate server activity
    // server_peer.endConnection();
    // std::this_thread::sleep_for(std::chrono::seconds(3)); // Simulate server activity
  });

  // Peer 2: Client
  std::thread client_thread([&]() {
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Client thread started.\n";
    }

    // Wait for the server to be ready
    {
      std::unique_lock<std::mutex> lock(sync_mutex);
      server_ready_cv.wait(lock, [&]() { return server_ready; });
    }

    Peer client_peer;
    {
      std::lock_guard<std::mutex> lock(cout_mutex);
      std::cout << "Starting client peer...\n";
    }

    // Start the client and send a message
    client_peer.startPeer();
    client_peer.sendMessage("Site-ul are în pagina (pagina textit) două butoare disponibile extit șiextit, al doilea "
                             "fiind pentru crearea de utilizator nou al aplicației (orice utilizator va trebui să-și facă cont pentru a putea cumpăra bilete), "
                             "iar primul pentru a te conecta la un cont deja existent. "
                             "Pentru conectarea la un cont este nevoie doar de textitși de textit{parola} contului. Conectarea la un cont ne va oferi "
                             "posibilitatea de a vizualiza istoricul biletelor cumpărate (dacă există), cursele ce vor avea loc și lista locurilor libere din avion. "
                             "Prin apăsarea pe un loc liber, acel bilet va fi adaugat în coșul utilizatorului. Această acțiune poate fi repetată pentru posibilitatea "
                             "cumpărării a multiple bilete simultan. "
                             "Dacă în coș se află cel puțin un bilet, vor apărea două butoane: textit{} și textit{}, ce vor oferi posibilitatea de a șterge din coșul "
                             "curent biletul selectat, dar și de a finaliza cumpărarea, adăugând biletele în istoric și golind coșul.");
    std::this_thread::sleep_for(std::chrono::seconds(3));
    client_peer.sendMessage("   Site-ul are în pagina (pagina textit) două butoare disponibile extit șiextit, al doilea "
                             "fiind pentru crearea de utilizator nou al aplicației (orice utilizator va trebui să-și facă cont pentru a putea cumpăra bilete), "
                             "iar primul pentru a te conecta la un cont deja existent. "
                             "Pentru conectarea la un cont este nevoie doar de textitși de textit{parola} contului. Conectarea la un cont ne va oferi "
                             "posibilitatea de a vizualiza istoricul biletelor cumpărate (dacă există), cursele ce vor avea loc și lista locurilor libere din avion. "
                             "Prin apăsarea pe un loc liber, acel bilet va fi adaugat în coșul utilizatorului. Această acțiune poate fi repetată pentru posibilitatea "
                             "cumpărării a multiple bilete simultan. ");

    std::this_thread::sleep_for(std::chrono::seconds(3)); // Simulate server activity
    client_peer.endConnection();
  });

  // Wait for both threads to finish
  server_thread.join();
  client_thread.join();

  {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "Peer test completed.\n";
  }
}

// Global variables for the chat interface
std::vector<std::string> chat_messages;
std::string input_message;
std::string ip_address = "127.0.0.1"; // Default IP address
bool exit_exit = false;

// Function to initialize Dear ImGui
void initImGui(GLFWwindow* window) {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");
    ImGui::StyleColorsDark();
}

// Function to clean up Dear ImGui
void cleanupImGui() {
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
}

// Function to render the GUI
bool renderGUI(Peer& peer) {
  bool var_is_connected;
  {
    std::lock_guard<std::mutex>lock(peer.is_connected_mutex);
    var_is_connected = peer.is_connected;
  }
    if (!var_is_connected) {

        // Connection screen
        ImGui::Begin("Connect to Peer");
        ImGui::Text("Enter the IP address of the peer you want to connect to:");

        // Input box for IP address
        static char ip_buffer[16] = "192.168.0.114"; // Buffer for IP address (max length 15 + null terminator)
        ImGui::InputText("IP Address", ip_buffer, sizeof(ip_buffer));

        // Connect button
        if (ImGui::Button("Connect")) {
            std::string ip_address(ip_buffer);

            {
              std::lock_guard<std::mutex>lock(peer.cout_mutex);
              std::cout<<"Connecting\n";
            }

            // Validate IP address length
            if (ip_address.length() >= 7 && ip_address.length() <= 15) {

                {
                  std::lock_guard<std::mutex>lock(peer.cout_mutex);
                  std::cout<<"Valid ip\n";
                }

                peer.connectToPeer(ip_address.c_str());
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                {
                  std::lock_guard<std::mutex>lock(peer.is_connected_mutex);
                  var_is_connected = peer.is_connected;
                }
                if (var_is_connected) {
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Connected successfully!");
                } else {
                    ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Failed to connect. Please try again.");
                }
            } else {

                {
                  std::lock_guard<std::mutex>lock(peer.cout_mutex);
                  std::cout<<"Invalid IP :(\n";
                }

                // Display an error message if the IP address is invalid
                ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Invalid IP address length! Must be between 4 and 12 characters.");
            }
        }

        ImGui::End();
    } else {

        exit_exit = true;

        // Chat screen
        ImGui::Begin("Chat Interface", nullptr, ImGuiWindowFlags_NoResize);

        // Display chat messages
        ImGui::BeginChild("ChatWindow", ImVec2(0, ImGui::GetWindowHeight() - 150), true);
        for (const auto& message : chat_messages) {
            ImGui::TextWrapped("%s", message.c_str());
        }
        ImGui::EndChild();

        // Input box for sending messages
        static std::string message_buffer; // Use std::string for dynamic allocation
        char input_buffer[1024];           // Temporary buffer for ImGui input

        // Copy the current content of message_buffer to input_buffer
        strncpy(input_buffer, message_buffer.c_str(), sizeof(input_buffer));
        input_buffer[sizeof(input_buffer) - 1] = '\0'; // Ensure null termination

        if (ImGui::InputText("Message", input_buffer, sizeof(input_buffer))) {
            // Update message_buffer with the new input
            message_buffer = input_buffer;
        }

        if (ImGui::Button("Send")) {
            if (!message_buffer.empty()) {
                peer.sendMessage(message_buffer); // Send the message
                chat_messages.push_back("You: " + message_buffer); // Add to chat history
                message_buffer.clear(); // Clear the input buffer
            }
        }

        // Input box for file location
        static char file_buffer[512] = ""; // Buffer for file path input
        ImGui::InputText("File Path", file_buffer, sizeof(file_buffer));
        if (ImGui::Button("Send File")) {
            std::string file_path(file_buffer);
            peer.sendFile(file_path);
            chat_messages.push_back("You sent a file: " + file_path);
            memset(file_buffer, 0, sizeof(file_buffer)); // Clear the input buffer
        }

        // Back button to disconnect and return to the connection screen
        if (ImGui::Button("Back")) {
            peer.endConnection(); // End the connection
            chat_messages.clear(); // Clear chat messages
              std::this_thread::sleep_for(std::chrono::milliseconds(200));
          {
            std::lock_guard<std::mutex> lock(peer.is_connected_mutex);
            peer.is_connected = false;
          }
          return false;
        }

        ImGui::End();
    }

    bool is_con = false;
    {
      std::lock_guard<std::mutex> lock(peer.is_connected_mutex);
      is_con = peer.is_connected;
    }

    bool exitin = false;
    {
      std::lock_guard<std::mutex> lock(peer.exiting_mutex);
      exitin = peer.exiting;
    }

    if (!is_con && exitin) {
      chat_messages.clear(); // Clear chat messages
      return false;
    }

    return true;
}

int main() {
    
  while (true){
    {

      // Initialize Peer
      Peer peer;

      peer.startPeer();

      // Start a thread to listen for incoming packets
      std::thread listener_thread([&peer]() {
          peer.listenForPackets();
      });

      std::thread processor_thread([&peer]() {
        peer.processPackets();
      });

      // Start a thread to print received messages
      std::thread message_printer_thread([&peer]() {

          // bool var_is_connected;
          // {
          //   std::lock_guard<std::mutex> lock(is_connected_mutex);
          //   var_is_connected = this->is_connected;
          // }
          while (true) {
            std::string received_message = peer.get_messages_received();

            if (received_message == "Aw12@0986^12luAwCluhWQ123~~``!") {
              {
                std::lock_guard<std::mutex> lock(peer.cout_mutex);
                std::cout << "Received wierd message\n";
              }
              break;
            }

              {
                std::lock_guard<std::mutex> lock(peer.cout_mutex);
                std::cout << "\n[Received Message]: " << received_message << "\n\n";
              }

              std::this_thread::sleep_for(std::chrono::milliseconds(100));

              chat_messages.push_back(received_message);
              // for (const auto &msg :peer.messages_received) {
              //   std::lock_guard<std::mutex> lock(peer.cout_mutex);
              //   // std::lock_guard<std::mutex> lock(peer.adding_msg_received);
              //   std::cout<<msg<<std::endl;
              // }

              // print_commands_options();

            // {
            //   std::lock_guard<std::mutex> lock(is_connected_mutex);
            //   var_is_connected = this->is_connected;
            // }
          }
      });

      // Initialize GLFW
      if (!glfwInit()) {
          return -1;
      }

      // Create a windowed mode window and its OpenGL context
      GLFWwindow* window = glfwCreateWindow(800, 600, "Peer Chat", NULL, NULL);
      if (!window) {
          glfwTerminate();
          return -1;
      }

      glfwMakeContextCurrent(window);
      glfwSwapInterval(1);

      // Initialize Dear ImGui
      initImGui(window);

      // Main loop
      while (!glfwWindowShouldClose(window)) {
          glfwPollEvents();

          // Start the Dear ImGui frame
          ImGui_ImplOpenGL3_NewFrame();
          ImGui_ImplGlfw_NewFrame();
          ImGui::NewFrame();

          // Render the GUI
          if (!renderGUI(peer)) break;

          // Rendering
          ImGui::Render();
          int display_w, display_h;
          glfwGetFramebufferSize(window, &display_w, &display_h);
          glViewport(0, 0, display_w, display_h);
          glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
          glClear(GL_COLOR_BUFFER_BIT);
          ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

          glfwSwapBuffers(window);
      }

      // Cleanup
      cleanupImGui();
      glfwDestroyWindow(window);
      glfwTerminate();

      // Wait for the listener thread to finish
      if (listener_thread.joinable()) {
          listener_thread.join();
          std::cout << "[Thread Ended]: Listener thread has finished.\n";
      }

      // Wait for the processor thread to finish
      if (processor_thread.joinable()) {
          processor_thread.join();
          std::cout << "[Thread Ended]: Processor thread has finished.\n";
      }

      // Wait for the message printer thread to finish
      if (message_printer_thread.joinable()) {
          message_printer_thread.join();
          std::cout << "[Thread Ended]: Message printer thread has finished.\n";
      }

      std::cout << "End";

      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }
    return 0;
}
