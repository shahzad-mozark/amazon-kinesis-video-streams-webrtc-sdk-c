#include "Samples.h"
#include <libavcodec/avcodec.h>
#include <libavcodec/codec.h>
#include <libavcodec/codec_id.h>
#include <libavcodec/codec_par.h>
#include <libavcodec/packet.h>
#include <libavformat/avformat.h>
#include <libavformat/avio.h>
#include <libavutil/avutil.h>
#include <libavutil/mem.h>
#include <libavutil/opt.h>
#include <libavutil/pixdesc.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

VOID onDataMessage(UINT64 customData, PRtcDataChannel pDataChannel, BOOL isBinary, PBYTE pMessage, UINT32 pMessageLen)
{
    UNUSED_PARAM(customData);
    UNUSED_PARAM(pDataChannel);
    if (isBinary) {
        DLOGI("DataChannel Binary Message");
    } else {
        printf("%s\n", pMessage);
        /*DLOGI("DataChannel String Message: %.*s\n", pMessageLen, pMessage);*/
    }
    // Send a response to the message sent by the viewer
    STATUS retStatus = STATUS_SUCCESS;
    retStatus = dataChannelSend(pDataChannel, FALSE, (PBYTE) MASTER_DATA_CHANNEL_MESSAGE, STRLEN(MASTER_DATA_CHANNEL_MESSAGE));
    if (retStatus != STATUS_SUCCESS) {
        DLOGI("[KVS Master] dataChannelSend(): operation returned status code: 0x%08x \n", retStatus);
    }
}

VOID OnDc(UINT64 customData, PRtcDataChannel pRtcDataChannel)
{
    dataChannelOnMessage(pRtcDataChannel, customData, onDataMessage);
}

extern PSampleConfiguration gSampleConfiguration;

// #define VERBOSE
FILE* fp;
AVFormatContext* context;
uint8_t* inbuff;
AVIOContext* iocontext;
volatile int fakeread_conditionvar = 0;
AVPacket* packet;
AVPacket* packets[10];

int read_frame(void* opaque, uint8_t* buff, int buff_size)
{
    int bytesRead = read(fileno(stdin), buff, buff_size);
    if (bytesRead == 0)
        return -1;
    return bytesRead;
}
void* fakeStdinRead();
INT32 main(INT32 argc, CHAR* argv[])
{
    pthread_t fakeReadThread;
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 frameSize;
    PSampleConfiguration pSampleConfiguration = NULL;
    SignalingClientMetrics signalingClientMetrics;
    PCHAR pChannelName;
    signalingClientMetrics.version = SIGNALING_CLIENT_METRICS_CURRENT_VERSION;
    SET_INSTRUMENTED_ALLOCATORS();

#ifndef _WIN32
    signal(SIGINT, sigintHandler);
#endif

    // do trickleIce by default
    printf("[KVS Master] Using trickleICE by default\n");

#ifdef IOT_CORE_ENABLE_CREDENTIALS
    CHK_ERR((pChannelName = getenv(IOT_CORE_THING_NAME)) != NULL, STATUS_INVALID_OPERATION, "AWS_IOT_CORE_THING_NAME must be set");
#else
    pChannelName = argc > 1 ? argv[1] : SAMPLE_CHANNEL_NAME;
#endif

    retStatus = createSampleConfiguration(pChannelName, SIGNALING_CHANNEL_ROLE_TYPE_MASTER, TRUE, TRUE, &pSampleConfiguration);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS Master] createSampleConfiguration(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }

    printf("[KVS Master] Created signaling channel %s\n", pChannelName);

    if (pSampleConfiguration->enableFileLogging) {
        retStatus =
            createFileLogger(FILE_LOGGING_BUFFER_SIZE, MAX_NUMBER_OF_LOG_FILES, (PCHAR) FILE_LOGGER_LOG_FILE_DIRECTORY_PATH, TRUE, TRUE, NULL);
        if (retStatus != STATUS_SUCCESS) {
            printf("[KVS Master] createFileLogger(): operation returned status code: 0x%08x \n", retStatus);
            pSampleConfiguration->enableFileLogging = FALSE;
        }
    }

    // Set the audio and video handlers
    pSampleConfiguration->audioSource = sendAudioPackets;
    pSampleConfiguration->videoSource = sendVideoPackets;
    pSampleConfiguration->receiveAudioVideoSource = sampleReceiveVideoFrame;
    pSampleConfiguration->onDataChannel = OnDc;
    pSampleConfiguration->mediaType = SAMPLE_STREAMING_AUDIO_VIDEO;
    printf("[KVS Master] Finished setting audio and video handlers\n");

    // Check if the samples are present
    context = avformat_alloc_context();
    inbuff = av_malloc(32879);
    iocontext = NULL;
    iocontext = avio_alloc_context(inbuff, 32879, 0, NULL, read_frame, NULL, NULL);
    context->pb = iocontext;
    context->flags = AVFMT_FLAG_CUSTOM_IO;
    avformat_open_input(&context, "whatever", NULL, NULL);
    printf("%s, %ld\n", context->iformat->long_name, context->duration);
    avformat_find_stream_info(context, NULL);
    AVCodecParameters* localcodecparams = NULL;
    AVCodec* localCodec;
    for (int i = 0; i < context->nb_streams; i++) {
        localcodecparams = context->streams[i]->codecpar;
        if (localcodecparams->codec_type == AVMEDIA_TYPE_VIDEO) {
            localCodec = (AVCodec*) avcodec_find_decoder(localcodecparams->codec_id);
            break;
        }
    }
    if (localcodecparams == NULL) {
        printf("no video src found\n");
        return -1;
    }
    AVCodecContext* codec_context = avcodec_alloc_context3(localCodec);
    avcodec_parameters_to_context(codec_context, localcodecparams);
    avcodec_open2(codec_context, localCodec, NULL);
    packet = av_packet_alloc();
    // assuming the first frame will always be there when the program starts
    // av_read_frame always reads something, if data is not at stdin then it will wait till there is data in stdin the program might hang here if the
    // pipe is not sending any data
    /*printf("reading for the frame\n");*/
    /*if (av_read_frame(context, packet) != STATUS_SUCCESS) {*/
    /*if (packet->size <= 0) {*/
    /*printf("no frames in stdin\n");*/
    /*return 0;*/
    /*}*/
    /*};*/
    /*printf("[KVS Master] Frame present in stdin\n");*/
    /*packets[0] = av_packet_alloc();*/
    /*memcpy(packets[0], packet, sizeof(*packet));*/
    /*for (int i = 1; i < 10; i++) {*/
    /*if (av_read_frame(context, packet) != STATUS_SUCCESS) {*/
    /*if (packet->size <= 0) {*/
    /*printf("no frames in stdin\n");*/
    /*usleep(1 / 15);*/
    /*}*/
    /*};*/
    /*packets[i] = av_packet_alloc();*/
    /*memcpy(packets[i], packet, sizeof(*packet));*/
    /*}*/
    /*pthread_create(&fakeReadThread, NULL, fakeStdinRead, NULL);*/
    /*retStatus = readFrameFromDisk(NULL, &frameSize, "./opusSampleFrames/sample-001.opus");*/
    /*if (retStatus != STATUS_SUCCESS) {*/
    /*printf("[KVS Master] readFrameFromDisk(): operation returned status code: 0x%08x \n", retStatus);*/
    /*goto CleanUp;*/
    /*}*/
    /*printf("[KVS Master] Checked sample audio frame availability....available\n");*/

    // Initialize KVS WebRTC. This must be done before anything else, and must only be done once.
    retStatus = initKvsWebRtc();
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS Master] initKvsWebRtc(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }
    printf("[KVS Master] KVS WebRTC initialization completed successfully\n");

    pSampleConfiguration->signalingClientCallbacks.messageReceivedFn = signalingMessageReceived;

    strcpy(pSampleConfiguration->clientInfo.clientId, SAMPLE_MASTER_CLIENT_ID);

    retStatus = createSignalingClientSync(&pSampleConfiguration->clientInfo, &pSampleConfiguration->channelInfo,
                                          &pSampleConfiguration->signalingClientCallbacks, pSampleConfiguration->pCredentialProvider,
                                          &pSampleConfiguration->signalingClientHandle);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS Master] createSignalingClientSync(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }
    printf("[KVS Master] Signaling client created successfully\n");

    // Enable the processing of the messages
    retStatus = signalingClientFetchSync(pSampleConfiguration->signalingClientHandle);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS Master] signalingClientFetchSync(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }

    retStatus = signalingClientConnectSync(pSampleConfiguration->signalingClientHandle);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS Master] signalingClientConnectSync(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }
    printf("[KVS Master] Signaling client connection to socket established\n");

    gSampleConfiguration = pSampleConfiguration;

    printf("[KVS Master] Channel %s set up done \n", pChannelName);
    // Checking for termination
    retStatus = sessionCleanupWait(pSampleConfiguration);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS Master] sessionCleanupWait(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }

    printf("[KVS Master] Streaming session terminated\n");

CleanUp:

    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS Master] Terminated with status code 0x%08x\n", retStatus);
    }

    printf("[KVS Master] Cleaning up....\n");
    if (pSampleConfiguration != NULL) {
        // Kick of the termination sequence
        ATOMIC_STORE_BOOL(&pSampleConfiguration->appTerminateFlag, TRUE);

        if (IS_VALID_MUTEX_VALUE(pSampleConfiguration->sampleConfigurationObjLock)) {
            MUTEX_LOCK(pSampleConfiguration->sampleConfigurationObjLock);
        }

        // Cancel the media thread
        if (pSampleConfiguration->mediaThreadStarted) {
            DLOGD("Canceling media thread");
            THREAD_CANCEL(pSampleConfiguration->mediaSenderTid);
        }

        if (IS_VALID_MUTEX_VALUE(pSampleConfiguration->sampleConfigurationObjLock)) {
            MUTEX_UNLOCK(pSampleConfiguration->sampleConfigurationObjLock);
        }

        if (pSampleConfiguration->mediaSenderTid != INVALID_TID_VALUE) {
            THREAD_JOIN(pSampleConfiguration->mediaSenderTid, NULL);
        }

        if (pSampleConfiguration->enableFileLogging) {
            freeFileLogger();
        }
        retStatus = signalingClientGetMetrics(pSampleConfiguration->signalingClientHandle, &signalingClientMetrics);
        if (retStatus == STATUS_SUCCESS) {
            logSignalingClientStats(&signalingClientMetrics);
        } else {
            printf("[KVS Master] signalingClientGetMetrics() operation returned status code: 0x%08x\n", retStatus);
        }
        retStatus = freeSignalingClient(&pSampleConfiguration->signalingClientHandle);
        if (retStatus != STATUS_SUCCESS) {
            printf("[KVS Master] freeSignalingClient(): operation returned status code: 0x%08x", retStatus);
        }

        retStatus = freeSampleConfiguration(&pSampleConfiguration);
        if (retStatus != STATUS_SUCCESS) {
            printf("[KVS Master] freeSampleConfiguration(): operation returned status code: 0x%08x", retStatus);
        }
    }
    printf("[KVS Master] Cleanup done\n");

    RESET_INSTRUMENTED_ALLOCATORS();

    // https://www.gnu.org/software/libc/manual/html_node/Exit-Status.html
    // We can only return with 0 - 127. Some platforms treat exit code >= 128
    // to be a success code, which might give an unintended behaviour.
    // Some platforms also treat 1 or 0 differently, so it's better to use
    // EXIT_FAILURE and EXIT_SUCCESS macros for portability.
    return STATUS_FAILED(retStatus) ? EXIT_FAILURE : EXIT_SUCCESS;
}
void* fakeStdinRead()
{
    printf("starting fake read\n");
    while (1) {
        usleep(1 / 15);
        av_read_frame(context, packet);
        if (fakeread_conditionvar == 1) {
            break;
        }
    }
    printf("ending fake read\n");

    return NULL;
    /*int MAX_READ_BUF = 32879; BYTE b[MAX_READ_BUF];*/
    /*while (1) {*/
    /*read(fileno(stdin), b, MAX_READ_BUF);*/
    /*if (fakeread_conditionvar == 1) {*/
    /*break;*/
    /*}*/
    /*}*/
    /*printf("fake read ended\n");*/
    /*return NULL;*/
}
/*STATUS ReadFromStdin(PBYTE Frame, PUINT32 Size)*/
/*{*/
/*printf("calling\n");*/
/*[>int bytesRead = read(fileno(stdin), Frame, 0x500000);<]*/
/*int bytesRead = read(fileno(stdin), Frame, 0x500000);*/
/**Size = bytesRead;*/
/*if (bytesRead < 0) {*/
/*printf("[KVS Master] ReadFromStdin(): read failed with the errno code 0x%x \n", errno);*/
/*return -1;*/
/*}*/
/*if (bytesRead == 0) {*/
/*printf("[KVS Master] ReadFromStdin(): zero bytes Read \n");*/
/*return -1;*/
/*}*/
/*printf("%d\n", bytesRead);*/
/*fwrite(Frame, sizeof(BYTE), bytesRead, fp);*/

/*return STATUS_SUCCESS;*/
/*}*/

STATUS readFrameFromDisk(PBYTE pFrame, PUINT32 pSize, PCHAR frameFilePath)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 size = 0;

    if (pSize == NULL) {
        printf("[KVS Master] readFrameFromDisk(): operation returned status code: 0x%08x \n", STATUS_NULL_ARG);
        goto CleanUp;
    }

    size = *pSize;

    // Get the size and read into frame
    retStatus = readFile(frameFilePath, TRUE, pFrame, &size);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS Master] readFile(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }

CleanUp:

    if (pSize != NULL) {
        *pSize = (UINT32) size;
    }

    return retStatus;
}

PVOID sendVideoPackets(PVOID args)
{
    fakeread_conditionvar = 1;
    PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;
    RtcEncoderStats encoderStats;
    Frame frame;
    UINT32 fileIndex = 0, frameSize;
    CHAR filePath[MAX_PATH_LEN + 1];
    STATUS status;
    UINT32 i;
    UINT64 startTime, lastFrameTime, elapsed;
    MEMSET(&encoderStats, 0x00, SIZEOF(RtcEncoderStats));

    if (pSampleConfiguration == NULL) {
        printf("[KVS Master] sendVideoPackets(): operation returned status code: 0x%08x \n", STATUS_NULL_ARG);
        goto CleanUp;
    }

    frame.presentationTs = 0;
    startTime = GETTIME();
    lastFrameTime = startTime;

    while (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag)) {
        /*if (packets[0] != NULL) {*/
        /*AVPacket* TempPacket;*/
        /*for (int j = 0; j < 10; j++) {*/
        /*TempPacket = packets[j];*/
        /*printf("reading buffer %d\n", j);*/
        /*pSampleConfiguration->pVideoFrameBuffer = TempPacket->data;*/
        /*pSampleConfiguration->videoBufferSize = TempPacket->size;*/
        /*frame.frameData = pSampleConfiguration->pVideoFrameBuffer;*/
        /*frame.size = TempPacket->size;*/

        /*// based on bitrate of samples/h264SampleFrames/frame-**/
        /*encoderStats.width = 640;*/
        /*encoderStats.height = 480;*/
        /*encoderStats.targetBitrate = 262000;*/
        /*frame.presentationTs += SAMPLE_VIDEO_FRAME_DURATION;*/

        /*MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);*/
        /*for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {*/
        /*status = writeFrame(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &frame);*/
        /*encoderStats.encodeTimeMsec = 4; // update encode time to an arbitrary number to demonstrate stats update*/
        /*updateEncoderStats(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &encoderStats);*/
        /*if (status != STATUS_SRTP_NOT_READY_YET) {*/
        /*if (status != STATUS_SUCCESS) {*/
        /*#ifdef VERBOSE*/
        /*printf("writeFrame() failed with 0x%08x\n", status);*/
        /*#endif*/
        /*}*/
        /*}*/
        /*}*/
        /*MUTEX_UNLOCK(pSampleConfiguration->streamingSessionListReadLock);*/

        /*// Adjust sleep in the case the sleep itself and writeFrame take longer than expected. Since sleep makes sure that the thread*/
        /*// will be paused at least until the given amount, we can assume that there's no too early frame scenario.*/
        /*// Also, it's very unlikely to have a delay greater than SAMPLE_VIDEO_FRAME_DURATION, so the logic assumes that this is always*/
        /*// true for simplicity.*/
        /*elapsed = lastFrameTime - startTime;*/
        /*THREAD_SLEEP(SAMPLE_VIDEO_FRAME_DURATION - elapsed % SAMPLE_VIDEO_FRAME_DURATION);*/
        /*lastFrameTime = GETTIME();*/
        /*av_packet_free(&packets[j]);*/
        /*packets[j] = NULL;*/
        /*}*/
        /*}*/
        /*printf("okeeeeeh\n");*/
        /*printf("okeeh\n");*/
        while (av_read_frame(context, packet) != STATUS_SUCCESS) {
            usleep(1 / 15);
            /*printf("read frame failed!");*/
        }
        pSampleConfiguration->pVideoFrameBuffer = packet->data;
        pSampleConfiguration->videoBufferSize = packet->size;
        frame.frameData = pSampleConfiguration->pVideoFrameBuffer;
        frame.size = packet->size;

        // based on bitrate of samples/h264SampleFrames/frame-*
        encoderStats.width = 640;
        encoderStats.height = 480;
        encoderStats.targetBitrate = 262000;
        frame.presentationTs += SAMPLE_VIDEO_FRAME_DURATION;

        MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);
        for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {
            status = writeFrame(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &frame);
            encoderStats.encodeTimeMsec = 4; // update encode time to an arbitrary number to demonstrate stats update
            updateEncoderStats(pSampleConfiguration->sampleStreamingSessionList[i]->pVideoRtcRtpTransceiver, &encoderStats);
            if (status != STATUS_SRTP_NOT_READY_YET) {
                if (status != STATUS_SUCCESS) {
#ifdef VERBOSE
                    printf("writeFrame() failed with 0x%08x\n", status);
#endif
                }
            }
        }
        MUTEX_UNLOCK(pSampleConfiguration->streamingSessionListReadLock);

        // Adjust sleep in the case the sleep itself and writeFrame take longer than expected. Since sleep makes sure that the thread
        // will be paused at least until the given amount, we can assume that there's no too early frame scenario.
        // Also, it's very unlikely to have a delay greater than SAMPLE_VIDEO_FRAME_DURATION, so the logic assumes that this is always
        // true for simplicity.
        elapsed = lastFrameTime - startTime;
        /*THREAD_SLEEP(SAMPLE_VIDEO_FRAME_DURATION - elapsed % SAMPLE_VIDEO_FRAME_DURATION);*/
        lastFrameTime = GETTIME();
    }
CleanUp:

    /*CHK_LOG_ERR(retStatus);*/

    /*return (PVOID) (ULONG_PTR) retStatus;*/
    return STATUS_SUCCESS;
}

PVOID sendAudioPackets(PVOID args)
{
    /*STATUS retStatus = STATUS_SUCCESS;*/
    /*PSampleConfiguration pSampleConfiguration = (PSampleConfiguration) args;*/
    /*Frame frame;*/
    /*UINT32 fileIndex = 0, frameSize;*/
    /*CHAR filePath[MAX_PATH_LEN + 1];*/
    /*UINT32 i;*/
    /*STATUS status;*/

    /*if (pSampleConfiguration == NULL) {*/
    /*printf("[KVS Master] sendAudioPackets(): operation returned status code: 0x%08x \n", STATUS_NULL_ARG);*/
    /*goto CleanUp;*/
    /*}*/

    /*frame.presentationTs = 0;*/

    /*while (!ATOMIC_LOAD_BOOL(&pSampleConfiguration->appTerminateFlag)) {*/
    /*fileIndex = fileIndex % NUMBER_OF_OPUS_FRAME_FILES + 1;*/
    /*snprintf(filePath, MAX_PATH_LEN, "./opusSampleFrames/sample-%03d.opus", fileIndex);*/

    /*retStatus = readFrameFromDisk(NULL, &frameSize, filePath);*/
    /*if (retStatus != STATUS_SUCCESS) {*/
    /*printf("[KVS Master] readFrameFromDisk(): operation returned status code: 0x%08x \n", retStatus);*/
    /*goto CleanUp;*/
    /*}*/

    /*// Re-alloc if needed*/
    /*if (frameSize > pSampleConfiguration->audioBufferSize) {*/
    /*pSampleConfiguration->pAudioFrameBuffer = (UINT8*) MEMREALLOC(pSampleConfiguration->pAudioFrameBuffer, frameSize);*/
    /*if (pSampleConfiguration->pAudioFrameBuffer == NULL) {*/
    /*printf("[KVS Master] Audio frame Buffer reallocation failed...%s (code %d)\n", strerror(errno), errno);*/
    /*printf("[KVS Master] MEMREALLOC(): operation returned status code: 0x%08x \n", STATUS_NOT_ENOUGH_MEMORY);*/
    /*goto CleanUp;*/
    /*}*/
    /*}*/

    /*frame.frameData = pSampleConfiguration->pAudioFrameBuffer;*/
    /*frame.size = frameSize;*/

    /*retStatus = readFrameFromDisk(frame.frameData, &frameSize, filePath);*/
    /*if (retStatus != STATUS_SUCCESS) {*/
    /*printf("[KVS Master] readFrameFromDisk(): operation returned status code: 0x%08x \n", retStatus);*/
    /*goto CleanUp;*/
    /*}*/

    /*frame.presentationTs += SAMPLE_AUDIO_FRAME_DURATION;*/

    /*MUTEX_LOCK(pSampleConfiguration->streamingSessionListReadLock);*/
    /*for (i = 0; i < pSampleConfiguration->streamingSessionCount; ++i) {*/
    /*status = writeFrame(pSampleConfiguration->sampleStreamingSessionList[i]->pAudioRtcRtpTransceiver, &frame);*/
    /*if (status != STATUS_SRTP_NOT_READY_YET) {*/
    /*if (status != STATUS_SUCCESS) {*/
    /*#ifdef VERBOSE*/
    /*printf("writeFrame() failed with 0x%08x\n", status);*/
    /*#endif*/
    /*}*/
    /*}*/
    /*}*/
    /*MUTEX_UNLOCK(pSampleConfiguration->streamingSessionListReadLock);*/
    /*THREAD_SLEEP(SAMPLE_AUDIO_FRAME_DURATION);*/
    /*}*/

    /*CleanUp:*/

    /*return (PVOID) (ULONG_PTR) retStatus;*/
}

PVOID sampleReceiveVideoFrame(PVOID args)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSampleStreamingSession pSampleStreamingSession = (PSampleStreamingSession) args;
    if (pSampleStreamingSession == NULL) {
        printf("[KVS Master] sampleReceiveVideoFrame(): operation returned status code: 0x%08x \n", STATUS_NULL_ARG);
        goto CleanUp;
    }

    retStatus = transceiverOnFrame(pSampleStreamingSession->pVideoRtcRtpTransceiver, (UINT64) pSampleStreamingSession, sampleFrameHandler);
    if (retStatus != STATUS_SUCCESS) {
        printf("[KVS Master] transceiverOnFrame(): operation returned status code: 0x%08x \n", retStatus);
        goto CleanUp;
    }

CleanUp:

    return (PVOID) (ULONG_PTR) retStatus;
}
