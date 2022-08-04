/***************************************************************************
    \file ADM_vidResampleFps
    \author mean fixounet@free.fr
    \brief Simple filter that enforces output constant frame per second
    Can be used both to change fps of a movie or to enforce in case of drops
    or pulldown. In that case, the input is a mix of 24 & 30 fps, the output
    is fixed 24 fps.
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <math.h>
#include "ADM_default.h"
#include "ADM_coreVideoFilter.h"
#include "DIA_coreToolkit.h"
#include "DIA_factory.h"

#include "confResampleFps.h"
#include "confResampleFps_desc.cpp"
#include "motin.h"

#if 1
    #define aprintf(...) {}
#else
    #define aprintf ADM_info
#endif

typedef struct 
{
    const char *desc;
    uint32_t num;
    uint32_t den;
}PredefinedFps_t;

const PredefinedFps_t predefinedFps[]=
{
 {QT_TRANSLATE_NOOP("resampleFps","Custom"),         10000,1000},
 {QT_TRANSLATE_NOOP("resampleFps","25  (PAL)"),      25000,1000},
 {QT_TRANSLATE_NOOP("resampleFps","23.976 (Film)"),  24000,1001},
 {QT_TRANSLATE_NOOP("resampleFps","29.97 (NTSC)"),   30000,1001},
 {QT_TRANSLATE_NOOP("resampleFps","50 (Pal)"),       50000,1000},
 {QT_TRANSLATE_NOOP("resampleFps","59.94  (NTSC)"),  60000,1001}
};

#define nbPredefined (sizeof(predefinedFps)/sizeof(PredefinedFps_t))

/**
    \class resampleFps

*/
class  resampleFps:public ADM_coreVideoFilterCached
{
protected:
        confResampleFps     configuration;
        bool                updateIncrement(void);
        uint64_t            baseTime;
        ADMImage            *frames[2];
        bool                refill(void);   // Fetch next frame
        bool                prefillDone;        // If true we already have 2 frames fetched
        bool                validMotionEstimation;
        motin *             motinp;
public:
                            resampleFps(ADM_coreVideoFilter *previous,CONFcouple *conf);
                            ~resampleFps();
        bool                goToTime(uint64_t usSeek, bool fineSeek = false);
        virtual const char   *getConfiguration(void);                   /// Return  current configuration as a human readable string
        virtual bool         getNextFrame(uint32_t *fn,ADMImage *image);    /// Return the next image
        virtual bool         getCoupledConf(CONFcouple **couples) ;   /// Return the current filter configuration
		virtual void setCoupledConf(CONFcouple *couples);
        virtual bool         configure(void) ;           /// Start graphical user interface
};
//***********************************
// Add the hook to make it valid plugin
DECLARE_VIDEO_FILTER(   resampleFps,   // Class
                        1,0,0,              // Version
                        ADM_UI_ALL,         // UI
                        VF_TRANSFORM,            // Category
                        "resampleFps",            // internal name (must be uniq!)
                        QT_TRANSLATE_NOOP("resampleFps","Resample FPS"),            // Display name
                        QT_TRANSLATE_NOOP("resampleFps","Change and enforce FPS. Keep duration and sync.") // Description
                    );

/**
    \fn updateIncrement
    \brief FPS->TimeIncrement
*/
bool resampleFps::updateIncrement(void)
{
    float f=configuration.newFpsNum*1000;
    f/=configuration.newFpsDen;
    f+=0.49;
    info.frameIncrement=ADM_UsecFromFps1000((uint32_t)f);
    info.timeBaseDen=configuration.newFpsNum;
    info.timeBaseNum=configuration.newFpsDen;

    return true;
}
/**
    \fn getConfiguration
*/
const char *resampleFps::getConfiguration( void )
{
static char buf[256];
 const char * intpn = NULL;
 switch (configuration.interpolation)
 {
     case 0:
         intpn = "none";
         break;
     case 1:
         intpn = "blend";
         break;
     case 2:
         intpn = "motion compensation";
         break;
     default:
         intpn = "INVALID";
         break;
 }
 snprintf(buf,255," Resample to %2.2f fps. Interpolation: %s", (double)configuration.newFpsNum/configuration.newFpsDen, intpn);
 return buf;  
}
/**
    \fn ctor
*/
resampleFps::resampleFps(  ADM_coreVideoFilter *previous,CONFcouple *setup) : 
        ADM_coreVideoFilterCached(3,previous,setup)
{
    baseTime=0;
    prefillDone=false;
    validMotionEstimation=false;
    frames[0]=frames[1]=NULL;
    if(!setup || !ADM_paramLoad(setup,confResampleFps_param,&configuration))
    {
        // Default value
        configuration.mode=0;
        configuration.newFpsNum=ADM_Fps1000FromUs(previous->getInfo()->frameIncrement);
        configuration.newFpsDen=1000;
        configuration.interpolation=0;
    }
    if(!frames[0]) frames[0]=new ADMImageDefault(info.width,info.height);
    if(!frames[1]) frames[1]=new ADMImageDefault(info.width,info.height);
    motinp = new motin(info.width,info.height);
    updateIncrement();
}
/**
    \fn dtor

*/
resampleFps::~resampleFps()
{
    if(frames[0]) delete frames[0];
    if(frames[1]) delete frames[1];
    frames[0]=frames[1]=NULL;
    delete motinp;
}
/**
     \fn refill
     \brief fetch a new frame from source, shift the old one as "old"
    frames[0]=old
    frames[1]=new
*/
bool resampleFps::refill(void)
{
    validMotionEstimation = false;
    ADMImage *nw=frames[0];
    uint32_t img=0;
    frames[0]=frames[1];
    frames[1]=nw;
    if (!previousFilter->getNextFrame(&img,nw))
        return false;
    return true;
}
/**
    \fn goToTime
    \brief called when seeking. Need to cleanup our stuff.
*/
bool         resampleFps::goToTime(uint64_t usSeek, bool fineSeek)
{
    double scale=info.frameIncrement;
    scale/=(double)previousFilter->getInfo()->frameIncrement;
    usSeek*=scale;
    if(false==ADM_coreVideoFilterCached::goToTime(usSeek,fineSeek))
        return false;
    prefillDone=false;
    validMotionEstimation=false;
    return true;
}

/**
    \fn getCoupledConf
*/ 
bool         resampleFps::getCoupledConf(CONFcouple **couples)
{
    return ADM_paramSave(couples, confResampleFps_param,&configuration);
}

void resampleFps::setCoupledConf(CONFcouple *couples)
{
    ADM_paramLoad(couples, confResampleFps_param, &configuration);
}

/**
    \fn getNextFrame
*/
 bool         resampleFps::getNextFrame(uint32_t *fn,ADMImage *image)
{

    if(!prefillDone) // Empty, need 1/ to refill, 2/ to rebase
    {
          if(false==refill()) return false;
          baseTime=frames[1]->Pts;  // We start at the first frame
          if(false==refill()) return false;
          prefillDone=true;
    }
    double offset=configuration.newFpsDen;
    offset*=1000000LL;
    offset*=nextFrame;
    offset/=configuration.newFpsNum;
    offset+=0.49;
    uint64_t thisTime=baseTime+(uint64_t)offset;

again:
    
    uint64_t frame1Dts=frames[0]->Pts;
    uint64_t frame2Dts=frames[1]->Pts;
    aprintf("Frame : %d, timeIncrement %d ms, Wanted : %" PRIu64", available %" PRIu64" and %" PRIu64"\n",
                    nextFrame,info.frameIncrement/1000,thisTime,frame1Dts,frame2Dts);
    if(thisTime>frame1Dts && thisTime>frame2Dts)
    {
        if(false==refill()) return false;
        goto again;
    }
    if(thisTime<frame1Dts && thisTime<frame2Dts)
    {
        image->duplicate(frames[0]);
        image->Pts=thisTime;
        *fn=nextFrame++;
        return true;
    }
    if (configuration.interpolation > 0)
    {
        double diff1=(double)thisTime-double(frame1Dts);
        double diff2=(double)thisTime-double(frame2Dts);
        if(diff1<0) diff1=-diff1;
        if(diff2<0) diff2=-diff2;
        int bl1,bl2;
        bl1 = round((diff2/(diff1+diff2)) * 256.0);
        bl2 = round((diff1/(diff1+diff2)) * 256.0);
        if (bl1==0)
            image->duplicate(frames[1]);
        else
        if (bl2==0)
            image->duplicate(frames[0]);
        else
        {
            image->duplicate(frames[0]);
            for (int p=0; p<3; p++)
            {
                int width=image->GetWidth((ADM_PLANE)p); 
                int height=image->GetHeight((ADM_PLANE)p);
                int ipixel, bpixel;
                int istride = image->GetPitch((ADM_PLANE)p);
                int bstride = frames[1]->GetPitch((ADM_PLANE)p);
                uint8_t * iptr = image->GetWritePtr((ADM_PLANE)p);
                uint8_t * bptr = frames[1]->GetWritePtr((ADM_PLANE)p);
                for (int y=0; y<height; y++)
                {
                    for(int x=0; x<width; x++)
                    {
                        ipixel = iptr[x];
                        bpixel = bptr[x];
                        iptr[x] = (ipixel*bl1 + bpixel*bl2) >> 8;
                    }
                    iptr += istride;
                    bptr += bstride;
                }
            }
            
            if (configuration.interpolation == 2)
            {
                if (!validMotionEstimation)
                {
                    motinp->createPyramids(frames[0],frames[1]);
                    motinp->estimateMotion();
                    validMotionEstimation = true;
                }
                motinp->interpolate(image, bl2);
            }
        }
    } else {
    // In between, take closer
        double diff1=(double)thisTime-double(frame1Dts);
        double diff2=(double)thisTime-double(frame2Dts);
        if(diff1<0) diff1=-diff1;
        if(diff2<0) diff2=-diff2;
        int index=1;
        if(diff1<diff2) index=0;

        image->duplicate(frames[index]);
    }
    image->Pts=thisTime;
    *fn=nextFrame++;
    return true;
}
#if 0
  ADMImage *mysrc1=NULL;
  ADMImage *mysrc2=NULL;

  if(frame>=_info.nb_frames) return 0;
  // read uncompressed frame
  
  // What frame are we seeking ?
  double f;
  uint32_t page=_info.width*_info.height;
  
  f=frame;
  f*=_in->getInfo()->fps1000;
  f/=_param->newfps;
  
  if(!_param->use_linear)
  {
      uint32_t nw;
      
      nw=(uint32_t)floor(f+0.4);
      if(nw>_in->getInfo()->nb_frames-1)
        nw=_in->getInfo()->nb_frames-1;
    
      mysrc1=vidCache->getImage(nw);
      if(!mysrc1) return 0;
      
      memcpy(YPLANE(data),YPLANE(mysrc1),page);
      memcpy(UPLANE(data),UPLANE(mysrc1),page>>2);
      memcpy(VPLANE(data),VPLANE(mysrc1),page>>2);
    
      vidCache->unlockAll();
      
      return 1;
  }
  /* With linear blending */
  uint32_t nw;
  uint8_t lowweight;
  uint8_t highweight;
  
  double diff;
  
  nw=(uint32_t)floor(f);
  diff=f-floor(f);
  highweight = (uint8_t)floor(diff*256);
  lowweight = 256 - highweight;

  if(nw>=_in->getInfo()->nb_frames-1)
    {
      printf("[ResampleFps] In %u Out %u\n",frame,nw);
      nw=_in->getInfo()->nb_frames-1;
      highweight=0;
    }
  //printf("New:%lu old:%lu\n",frame,nw);

  if(highweight == 0)
    {
      mysrc1=vidCache->getImage(nw);  
      if(!mysrc1) return 0;
      
      memcpy(YPLANE(data),YPLANE(mysrc1),page);
      memcpy(UPLANE(data),UPLANE(mysrc1),page>>2);
      memcpy(VPLANE(data),VPLANE(mysrc1),page>>2);
      
      vidCache->unlockAll();
    }
  else
    {
      mysrc1=vidCache->getImage(nw);
      mysrc2=vidCache->getImage(nw+1);
      if(!mysrc1 || !mysrc2) return 0;
      
      uint8_t *out, *in1, *in2;
      uint32_t count;
      uint32_t idx;
      
      out = YPLANE(data);
      in1 = YPLANE(mysrc1);
      in2 = YPLANE(mysrc2);
        
      count = page;

#ifdef ADM_CPU_X86
        if(CpuCaps::hasMMX())
                blendMMX(in1,in2,out,lowweight,highweight,(count*3)>>1);
        else
#endif
      {
      for(idx = 0; idx < count; ++idx)
	out[idx] = ((in1[idx]*lowweight) + (in2[idx]*highweight))>>8;

      out = UPLANE(data);
      in1 = UPLANE(mysrc1);
      in2 = UPLANE(mysrc2);
      count = page>>2;

      for(idx = 0; idx < count; ++idx)
        out[idx] = ((in1[idx]*lowweight) + (in2[idx]*highweight))>>8;      


      out = VPLANE(data);
      in1 = VPLANE(mysrc1);
      in2 = VPLANE(mysrc2);
      count = page>>2;

      for(idx = 0; idx < count; ++idx)
	out[idx] = ((in1[idx]*lowweight) + (in2[idx]*highweight))>>8;
      }

      vidCache->unlockAll();
    }
  return 1;
}
#endif 
/**
    \fn configure
*/
bool resampleFps::configure(void)
{

    float f=configuration.newFpsNum; 
    f/=configuration.newFpsDen;

ADM_assert(nbPredefined == 6);

#define Z(x) {x, predefinedFps[x].desc, NULL}
    diaMenuEntry tFps[]={Z(0),Z(1),Z(2),Z(3),Z(4),Z(5)};

    diaMenuEntry tInterp[3]={
            {0,QT_TRANSLATE_NOOP("resampleFps","none"),NULL},
            {1,QT_TRANSLATE_NOOP("resampleFps","Blend"),NULL},
            {2,QT_TRANSLATE_NOOP("resampleFps","Motion compensation"),NULL}
    };
                          
    uint32_t sel=configuration.mode;
    

    diaElemMenu mFps(&(configuration.mode),   QT_TRANSLATE_NOOP("resampleFps","_Mode:"), 6,tFps);
    diaElemFloat fps(&f,QT_TRANSLATE_NOOP("resampleFps","_New frame rate:"),1,1000.);
    diaElemMenu mInterp(&(configuration.interpolation),   QT_TRANSLATE_NOOP("resampleFps","_Interpolation:"), 3,tInterp);

    mFps.link(tFps+0,1,&fps); // only activate entry in custom mode

    diaElem *elems[3]={&mFps,&fps,&mInterp};
  
    if( diaFactoryRun(QT_TRANSLATE_NOOP("resampleFps","Resample fps"),3,elems))
    {
      if(!configuration.mode) // Custom mode
      {
          f*=1000;
          configuration.newFpsNum=(uint32_t)floor(f+0.4);
          configuration.newFpsDen=(uint32_t)1000;
      }else   // Preset
        {
            const PredefinedFps_t *me=&(predefinedFps[configuration.mode]);
            configuration.newFpsNum=me->num;
            configuration.newFpsDen=me->den;
        }
      prefillDone=false;
      updateIncrement();
      return 1;
    }
    return 0;
}

//EOF
